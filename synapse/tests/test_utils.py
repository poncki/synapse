# -*- coding: utf-8 -*-
"""
synapse - test_utils.py.py
Created on 10/21/17.

Test for synapse.tests.utils classes
"""
import os
import time
import logging

import synapse.common as s_common

import synapse.lib.output as s_output

import synapse.tests.utils as s_t_utils

logger = logging.getLogger(__name__)

class TestUtils(s_t_utils.SynTest):
    def test_syntest_helpers(self):
        # Execute all of the test helpers here
        self.len(2, (1, 2))

        self.le(1, 2)
        self.le(1, 1)
        self.lt(1, 2)
        self.ge(2, 1)
        self.ge(1, 1)
        self.gt(2, 1)

        self.isin('foo', ('foo', 'bar'))
        self.isin('foo', 'fooobarr')
        self.isin('foo', {'foo': 'bar'})
        self.isin('foo', {'foo', 'bar'})
        self.isin('foo', ['foo', 'bar'])

        self.notin('baz', ('foo', 'bar'))
        self.notin('baz', 'fooobarr')
        self.notin('baz', {'foo': 'bar'})
        self.notin('baz', {'foo', 'bar'})
        self.notin('baz', ['foo', 'bar'])

        self.isinstance('str', str)
        self.isinstance('str', (str, dict))

        self.sorteq((1, 2, 3), [2, 3, 1])

        def div0():
            return 1 / 0

        self.raises(ZeroDivisionError, div0)

        self.none(None)
        self.none({'foo': 'bar'}.get('baz'))

        self.nn(1)
        self.nn({'foo': 'bar'}.get('baz', 'woah'))

        self.true(True)
        self.true(1)
        self.true(-1)
        self.true('str')

        self.false(False)
        self.false(0)
        self.false('')
        self.false(())
        self.false([])
        self.false({})
        self.false(set())

        self.eq(True, 1)
        self.eq(False, 0)
        self.eq('foo', 'foo')
        self.eq({'1', '2'}, {'2', '1', '2'})
        self.eq({'key': 'val'}, {'key': 'val'})

        self.ne(True, 0)
        self.ne(False, 1)
        self.ne('foo', 'foobar')
        self.ne({'1', '2'}, {'2', '1', '2', '3'})
        self.ne({'key': 'val'}, {'key2': 'val2'})

        self.noprop({'key': 'valu'}, 'foo')

        with self.getTestDir() as fdir:
            self.true(os.path.isdir(fdir))
        self.false(os.path.isdir(fdir))

        # try mirroring an arbitrary direcotry
        with self.getTestDir() as fdir1:
            with s_common.genfile(fdir1, 'hehe.haha') as fd:
                fd.write('hehe'.encode())
            with self.getTestDir(fdir1) as fdir2:
                with s_common.genfile(fdir2, 'hehe.haha') as fd:
                    self.eq(fd.read(), 'hehe'.encode())

        outp = self.getTestOutp()
        self.isinstance(outp, s_output.OutPut)

    def test_syntest_logstream(self):
        with self.getLoggerStream('synapse.tests.test_utils') as stream:
            logger.error('ruh roh i am a error message')
        stream.seek(0)
        mesgs = stream.read()
        self.isin('ruh roh', mesgs)

    def test_syntest_logstream_event(self):

        @s_common.firethread
        def logathing():
            time.sleep(0.01)
            logger.error('StreamEvent Test Message')

        logger.error('notthere')
        with self.getLoggerStream('synapse.tests.test_utils', 'Test Message') as stream:
            thr = logathing()
            self.true(stream.wait(10))
            thr.join()

        stream.seek(0)
        mesgs = stream.read()
        self.isin('StreamEvent Test Message', mesgs)
        self.notin('notthere', mesgs)

    def test_syntest_envars(self):
        os.environ['foo'] = '1'
        os.environ['bar'] = '2'

        with self.setTstEnvars(foo=1, bar='joke', baz=1234) as cm:
            self.none(cm)
            self.eq(os.environ.get('foo'), '1')
            self.eq(os.environ.get('bar'), 'joke')
            self.eq(os.environ.get('baz'), '1234')

        self.eq(os.environ.get('foo'), '1')
        self.eq(os.environ.get('bar'), '2')
        self.none(os.environ.get('baz'))

    def test_outp(self):
        outp = s_t_utils.TstOutPut()
        outp.printf('Test message #1!')
        outp.expect('#1')
        self.raises(Exception, outp.expect, 'oh my')

    def test_testenv(self):

        with s_t_utils.TstEnv() as env:

            foo = 'foo'
            env.add('foo', foo)

            self.true(env.foo is foo)

            def blah():
                env.blah

            self.raises(AttributeError, blah)

    async def test_cmdg_simple_sequence(self):
        cmdg = s_t_utils.CmdGenerator(['foo', 'bar'])
        self.eq(await cmdg(), 'foo')
        self.eq(await cmdg(), 'bar')
        with self.raises(Exception):
            await cmdg()

    async def test_cmdg_end_exception(self):
        cmdg = s_t_utils.CmdGenerator(['foo', 'bar', EOFError()])
        self.eq(await cmdg(), 'foo')
        self.eq(await cmdg(), 'bar')

        with self.raises(EOFError):
            await cmdg()

        with self.raises(Exception) as cm:
            await cmdg()
            self.assertIn('No further actions', str(cm.exception))

    def test_istufo(self):
        node = (None, {})
        self.istufo(node)
        node = ('1234', {})
        self.istufo(node)

        self.raises(AssertionError, self.istufo, [None, {}])
        self.raises(AssertionError, self.istufo, (None, {}, {}))
        self.raises(AssertionError, self.istufo, (1234, set()))
        self.raises(AssertionError, self.istufo, (None, set()))

    async def test_async(self):

        async def araiser():
            return 1 / 0

        await self.asyncraises(ZeroDivisionError, araiser())

    async def test_storm_mesgs(self):

        async with self.getTestCore() as core:
            mesgs = await core.streamstorm('[test:str=1234] | count').list()
            self.stormIsInPrint('Counted 1 nodes.', mesgs)

            mesgs = await core.streamstorm('iden newp').list()
            self.stormIsInWarn('Failed to decode iden', mesgs)