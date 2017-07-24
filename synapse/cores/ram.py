import collections

from synapse.compat import isint, intern

import synapse.cores.common as s_cores_common
import synapse.cores.storage as s_cores_storage

def initRamCortex(link):
    '''
    Initialize a RAM based Cortex from a link tufo.

    NOTE: the "path" element of the link tufo is used to
          potentially return an existing cortex instance.

    '''
    path = link[1].get('path').strip('/')
    if not path:
        return s_cores_common.Cortex(link, store=RamStorage)

    core = ramcores.get(path)
    if core is None:
        core = s_cores_common.Cortex(link, store=RamStorage)

        ramcores[path] = core
        def onfini():
            ramcores.pop(path, None)

        core.onfini(onfini)

    return core

class RamXact(s_cores_storage.StoreXact):

    # Ram Cortex fakes out the idea of xact...
    def _coreXactBegin(self):
        pass

    def _coreXactCommit(self):
        pass

class RamStorage(s_cores_storage.Storage):

    def _initCoreStor(self):
        self.rowsbyid = collections.defaultdict(set)
        self.rowsbyprop = collections.defaultdict(set)
        self.rowsbyvalu = collections.defaultdict(set)
        self._blob_store = {}

    def getStoreXact(self, size=None):
        return RamXact(self, size=size)

    def tufosByGe(self, prop, valu, limit=None):
        # FIXME sortedcontainers optimizations go here
        valu, _ = self.getPropNorm(prop, valu)
        rows = self.rowsByGe(prop, valu, limit=limit)
        return self.getTufosByIdens([r[0] for r in rows])

    def tufosByLe(self, prop, valu, limit=None):
        # FIXME sortedcontainers optimizations go here
        valu, _ = self.getPropNorm(prop, valu)
        rows = self.rowsByLe(prop, valu, limit=limit)
        return self.getTufosByIdens([r[0] for r in rows])

    def sizeByRange(self, prop, valu, limit=None):
        minval = int(self.getPropNorm(prop, valu[0])[0])
        maxval = int(self.getPropNorm(prop, valu[1])[0])
        return sum(1 for r in self.rowsbyprop.get(prop, ()) if isint(r[2]) and r[2] >= minval and r[2] < maxval)

    def rowsByRange(self, prop, valu, limit=None):
        minval = int(self.getPropNorm(prop, valu[0])[0])
        maxval = int(self.getPropNorm(prop, valu[1])[0])

        # HACK: for speed
        ret = [r for r in self.rowsbyprop.get(prop, ()) if isint(r[2]) and r[2] >= minval and r[2] < maxval]

        if limit is not None:
            ret = ret[:limit]

        return ret

    def sizeByGe(self, prop, valu, limit=None):
        return sum(1 for r in self.rowsbyprop.get(prop, ()) if isint(r[2]) and r[2] >= valu)

    def rowsByGe(self, prop, valu, limit=None):
        return [r for r in self.rowsbyprop.get(prop, ()) if isint(r[2]) and r[2] >= valu][:limit]

    def sizeByLe(self, prop, valu, limit=None):
        return sum(1 for r in self.rowsbyprop.get(prop, ()) if isint(r[2]) and r[2] <= valu)

    def rowsByLe(self, prop, valu, limit=None):
        return [r for r in self.rowsbyprop.get(prop, ()) if isint(r[2]) and r[2] <= valu][:limit]

    def _addRows(self, rows):
        for row in rows:
            row = (intern(row[0]), intern(row[1]), row[2], row[3])
            self.rowsbyid[row[0]].add(row)
            self.rowsbyprop[row[1]].add(row)
            self.rowsbyvalu[(row[1], row[2])].add(row)

    def _delRowsById(self, iden):
        for row in self.rowsbyid.pop(iden, ()):
            self._delRawRow(row)

    def _delRowsByIdProp(self, iden, prop, valu=None):
        if valu is None:
            rows = [row for row in self.rowsbyid.get(iden, ()) if row[1] == prop]
            [self._delRawRow(row) for row in rows]
            return

        rows = [row for row in self.rowsbyid.get(iden, ()) if row[1] == prop and row[2] == valu]
        [self._delRawRow(row) for row in rows]
        return

    def getRowsByIdProp(self, iden, prop, valu=None):
        if valu is None:
            return [row for row in self.rowsbyid.get(iden, ()) if row[1] == prop]

        return [row for row in self.rowsbyid.get(iden, ()) if row[1] == prop and row[2] == valu]

    def _delRowsByProp(self, prop, valu=None, mintime=None, maxtime=None):
        for row in self.getRowsByProp(prop, valu=valu, mintime=mintime, maxtime=maxtime):
            self._delRawRow(row)

    def _delRawRow(self, row):

        byid = self.rowsbyid.get(row[0])
        if byid is not None:
            byid.discard(row)

        byprop = self.rowsbyprop[row[1]]
        byprop.discard(row)
        if not byprop:
            self.rowsbyprop.pop(row[1], None)

        propvalu = (row[1], row[2])

        byvalu = self.rowsbyvalu[propvalu]
        byvalu.discard(row)
        if not byvalu:
            self.rowsbyvalu.pop(propvalu, None)

    def getRowsById(self, iden):
        return list(self.rowsbyid.get(iden, ()))

    def getRowsByProp(self, prop, valu=None, mintime=None, maxtime=None, limit=None):

        if valu is None:
            rows = self.rowsbyprop.get(prop)
        else:
            rows = self.rowsbyvalu.get((prop, valu))

        if rows is None:
            return

        c = 0
        # This was originally a set, but sets are mutable and throw
        # runtimeerrors if their size changes during iteration
        for row in tuple(rows):
            if mintime is not None and row[3] < mintime:
                continue

            if maxtime is not None and row[3] >= maxtime:
                continue

            yield row

            c += 1
            if limit is not None and c >= limit:
                break

    def getSizeByProp(self, prop, valu=None, mintime=None, maxtime=None):
        if valu is None:
            rows = self.rowsbyprop.get(prop)
        else:
            rows = self.rowsbyvalu.get((prop, valu))

        if rows is None:
            return 0

        if mintime is not None:
            rows = [row for row in rows if row[3] >= mintime]

        if maxtime is not None:
            rows = [row for row in rows if row[3] < maxtime]

        return len(rows)

    def getStoreType(self):
        return 'ram'

    def _getBlobValu(self, key):
        ret = self._blob_store.get(key)
        return ret

    def _setBlobValu(self, key, valu):
        self._blob_store[key] = valu

    def _hasBlobValu(self, key):
        return key in self._blob_store

    def _delBlobValu(self, key):
        ret = self._blob_store.pop(key)
        return ret

    def _getBlobKeys(self):
        ret = list(self._blob_store.keys())
        return ret

    def _genStoreRows(self):
        for iden, rows in self.rowsbyid.items():
            yield list(rows)

ramcores = {}
