# Copyright (c) 2014 Rackspace Hosting
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
import logging

# NOTE(jkoelker) Patch Vlog so that is uses standard logging
from ovs import vlog


class Vlog(vlog.Vlog):
    def __init__(self, name):
        self.log = logging.getLogger('ovs.%s' % name)

    def __log(self, level, message, **kwargs):
        level = vlog.LEVELS.get(level, logging.DEBUG)
        self.log.log(level, message, **kwargs)

vlog.Vlog = Vlog


from ovs import jsonrpc
from ovs import reconnect
from ovs import stream
from ovs import timeval
from ovs.db import idl

from ryu.base import app_manager
from ryu.lib import hub
from ryu.services.protocols.ovsdb import event
from ryu.services.protocols.ovsdb import model


now = timeval.msec


def dictify(row):
    if row is None:
        return {}

    return dict([(k, v.to_python(idl._uuid_to_row))
                 for k, v in row._data.iteritems()])


def build_transaction(idl_obj, txn_req):
    txn = idl.Transaction(idl_obj)

    for table in txn_req:
        if table is '_uuid':
            continue

        for row in txn_req[table]:
            row_obj = idl_obj.tables[table].rows.get(row.uuid)

            if row.delete:
                if row_obj:
                    row_obj.delete()

                continue

            if not row_obj:
                row_obj = txn.insert(table, row.uuid)

            for column, value in row.iteritems():
                if column is not '_uuid':
                    setattr(row_obj, column, value)

    return txn


def discover_schemas(connection):
    # NOTE(jkoelker) currently only the Open_vSwitch schema
    #                is supported.
    # TODO(jkoelker) support arbitrary schemas
    req = jsonrpc.Message.create_request('list_dbs', [])
    error, reply = connection.transact_block(req)

    if error or reply.error:
        # TODO(jkoelker) Error handling
        return

    schemas = []
    for db in reply.result:
        if db != 'Open_vSwitch':
            continue

        req = jsonrpc.Message.create_request('get_schema', [db])
        error, reply = connection.transact_block(req)

        if error or reply.error:
            # TODO(jkoelker) Error handling
            continue

        schemas.append(reply.result)

    return schemas


def discover_system_id(idl):
    system_id = None

    while system_id is None:
        idl.run()
        openvswitch = idl.tables['Open_vSwitch'].rows

        if openvswitch:
            row = openvswitch.get(openvswitch.keys()[0])
            system_id = row.external_ids.get('system-id')

    return system_id


# NOTE(jkoelker) Wrap ovs's Idl to accept an existing session, and
#                trigger callbacks on changes
class Idl(idl.Idl):
    def __init__(self, session, schema):
        if not isinstance(schema, idl.SchemaHelper):
            schema = idl.SchemaHelper(schema_json=schema)
            schema.register_all()

        schema = schema.get_idl_schema()

        # NOTE(jkoelker) event buffer
        self._events = []

        self.tables = schema.tables
        self._db = schema
        self._session = session
        self._monitor_request_id = None
        self._last_seqno = None
        self.change_seqno = 0

        # Database locking.
        self.lock_name = None          # Name of lock we need, None if none.
        self.has_lock = False          # Has db server said we have the lock?
        self.is_lock_contended = False  # Has db server said we can't get lock?
        self._lock_request_id = None   # JSON-RPC ID of in-flight lock request.

        # Transaction support.
        self.txn = None
        self._outstanding_txns = {}

        for table in schema.tables.itervalues():
            for column in table.columns.itervalues():
                if not hasattr(column, 'alert'):
                    column.alert = True
            table.need_table = False
            table.rows = {}
            table.idl = self

    @property
    def events(self):
        events = self._events
        self._events = []
        return events

    def __process_update(self, table, uuid, old, new):
        old_row = table.rows.get(uuid)

        changed = idl.Idl.__process_update(self, table, uuid, old, new)

        if changed:
            if not new:
                old_row = model.Row(dictify(old_row))
                old_row['_uuid'] = uuid
                ev = (event.EventRowDelete, (table, old_row))

            elif not old:
                new_row = model.Row(dictify(table.rows.get(uuid)))
                new_row['_uuid'] = uuid
                ev = (event.EventRowInsert, (table, new_row))

            else:
                old_row = model.Row(dictify(old_row))
                old_row['_uuid'] = uuid

                new_row = model.Row(dictify(table.rows.get(uuid)))
                new_row['_uuid'] = uuid

                ev = (event.EventRowUpdate, (table, old_row, new_row))

            self._events.append(ev)

        return changed


class RemoteOvsdb(app_manager.RyuApp):
    _EVENTS = [event.EventRowUpdate,
               event.EventRowDelete,
               event.EventRowInsert]

    @classmethod
    def factory(cls, sock, address, *args, **kwargs):
        ovs_stream = stream.Stream(sock, None, None)
        connection = jsonrpc.Connection(ovs_stream)
        schemas = discover_schemas(connection)

        if not schemas:
            return

        fsm = reconnect.Reconnect(now())
        fsm.set_name('%s:%s' % address)
        fsm.enable(now())
        fsm.set_passive(True, now())
        fsm.set_max_tries(-1)
        fsm.connected(now())

        session = jsonrpc.Session(fsm, connection)
        idl = Idl(session, schemas[0])

        system_id = discover_system_id(idl)
        name = cls.instance_name(system_id)
        ovs_stream.name = name
        connection.name = name
        fsm.set_name(name)

        kwargs = kwargs.copy()
        kwargs['address'] = address
        kwargs['idl'] = idl
        kwargs['name'] = name
        kwargs['system_id'] = system_id

        app_mgr = app_manager.AppManager.get_instance()
        return app_mgr.instantiate(cls, *args, **kwargs)

    @classmethod
    def instance_name(cls, system_id):
        return '%s-%s' % (cls.__name__, system_id)

    def __init__(self, *args, **kwargs):
        super(RemoteOvsdb, self).__init__(*args, **kwargs)
        self.address = kwargs['address']
        self._idl = kwargs['idl']
        self.system_id = kwargs['system_id']
        self.name = kwargs['name']
        self._txn_q = collections.deque()

    def _event_proxy_loop(self):
        while self.is_active:
            events = self._idl.events

            if not events:
                hub.sleep(0.1)
                continue

            for event in events:
                ev = event[0]
                args = event[1]
                self.send_event_to_observers(ev(self.system_id, *args))

            hub.sleep(0)

    def _idl_loop(self):
        while self.is_active:
            try:
                self._idl.run()
                self._transactions()
            except Exception:
                self.logger.exception('Error running IDL for system_id %s' %
                                      self.system_id)
                break

            hub.sleep(0)

    def _run_thread(self, func, *args, **kwargs):
        try:
            func(*args, **kwargs)

        finally:
            self.stop()

    def _transactions(self):
        if not self._txn_q:
            return

        # NOTE(jkoelker) possibly run multiple transactions per loop?
        self._transaction()

    def _transaction(self):
        txn_req, req = self._txn_q.popleft()
        txn = build_transaction(self._idl, txn_req)
        status = txn.commit_block()

        if status in (idl.Transaction.SUCCESS, idl.Transaction.UNCHANGED):
            for rows in txn_req.itervalues():
                if not isinstance(rows, collections.Iterable):
                    continue

                for row in rows:
                    row.ovs_uuid = txn.get_insert_uuid(row.uuid)

        rep = event.EventModifyReply(self.system_id, txn, status)
        self.reply_to_request(req, rep)

    def modify_request_handler(self, ev):
        txn = ev.txn

        if not isinstance(txn, model.Transaction):
            txn = model.Transaction(txn)

        txn._uuidize()
        self._txn_q.append((txn, ev))

    def read_request_handler(self, ev):
        table = {}
        if ev.table_name in self._idl.tables:
            rows = self._idl.tables[ev.table_name].rows
            table = dict((row_uuid, dictify(row))
                         for row_uuid, row in rows.iteritems())
        rep = event.EventReadReply(self.system_id, table)
        self.reply_to_request(ev, rep)

    def start(self):
        super(RemoteOvsdb, self).start()
        t = hub.spawn(self._run_thread, self._idl_loop)
        self.threads.append(t)

        t = hub.spawn(self._run_thread, self._event_proxy_loop)
        self.threads.append(t)

    def stop(self):
        super(RemoteOvsdb, self).stop()
        self._idl.close()
