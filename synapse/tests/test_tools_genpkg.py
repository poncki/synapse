import os

import synapse.exc as s_exc
import synapse.common as s_common
import synapse.tests.utils as s_test
import synapse.tests.files as s_files

import synapse.tools.genpkg as s_genpkg

dirname = os.path.dirname(__file__)

class GenPkgTest(s_test.SynTest):

    async def test_tools_genpkg(self):

        with self.raises(s_exc.NoSuchFile):
            ymlpath = s_common.genpath(dirname, 'files', 'stormpkg', 'nosuchfile.yaml')
            await s_genpkg.main((ymlpath,))

        with self.raises(s_exc.BadPkgDef):
            ymlpath = s_common.genpath(dirname, 'files', 'stormpkg', 'nopath.yaml')
            await s_genpkg.main((ymlpath,))

        with self.raises(s_exc.BadPkgDef):
            ymlpath = s_common.genpath(dirname, 'files', 'stormpkg', 'nomime.yaml')
            await s_genpkg.main((ymlpath,))

        with self.raises(s_exc.BadPkgDef):
            ymlpath = s_common.genpath(dirname, 'files', 'stormpkg', 'notitle.yaml')
            await s_genpkg.main((ymlpath,))

        with self.raises(s_exc.BadPkgDef):
            ymlpath = s_common.genpath(dirname, 'files', 'stormpkg', 'nocontent.yaml')
            await s_genpkg.main((ymlpath,))

        ymlpath = s_common.genpath(dirname, 'files', 'stormpkg', 'testpkg.yaml')
        async with self.getTestCore() as core:

            savepath = s_common.genpath(core.dirn, 'testpkg.json')
            yamlpath = s_common.genpath(core.dirn, 'testpkg.yaml')
            newppath = s_common.genpath(core.dirn, 'newp.yaml')

            url = core.getLocalUrl()
            argv = ('--push', url, '--save', savepath, ymlpath)

            await s_genpkg.main(argv)

            msgs = await core.stormlist('testpkgcmd')
            self.stormIsInPrint('argument <foo> is required', msgs)
            msgs = await core.stormlist('$mod=$lib.import(testmod) $lib.print($mod)')
            self.stormIsInPrint('Imported Module testmod', msgs)

            pdef = s_common.yamlload(savepath)
            s_common.yamlsave(pdef, yamlpath)

            self.eq(pdef['name'], 'testpkg')
            self.eq(pdef['version'], (0, 0, 1))
            self.eq(pdef['modules'][0]['name'], 'testmod')
            self.eq(pdef['modules'][0]['storm'], 'inet:ipv4\n')
            self.eq(pdef['modules'][1]['name'], 'testpkg.testext')
            self.eq(pdef['modules'][1]['storm'], 'inet:fqdn\n')
            self.eq(pdef['modules'][2]['name'], 'testpkg.testextfile')
            self.eq(pdef['modules'][2]['storm'], 'inet:fqdn\n')
            self.eq(pdef['commands'][0]['name'], 'testpkgcmd')
            self.eq(pdef['commands'][0]['storm'], 'inet:ipv6\n')

            self.eq(pdef['optic']['files']['index.html']['file'], 'aGkK')

            self.eq(pdef['docs'][0]['title'], 'Foo Bar')
            self.eq(pdef['docs'][0]['content'], 'Hello!\n')

            self.eq(pdef['logo']['mime'], 'image/svg')
            self.eq(pdef['logo']['file'], 'c3R1ZmYK')

            wflow = pdef['optic']['workflows']['310eb7324b5da268fb31e4cd3d74e673']
            self.eq(wflow, {'name': 'foo', 'desc': 'a foo workflow'})

            wflow = pdef['optic']['workflows']['41e3368bd094e1c1563a242bfa56bd01']
            self.eq(wflow, {'name': 'bar', 'desc': 'this is an inline workflow'})

            wflow = pdef['optic']['workflows']['bfb53cbaa789f2960de003d72b6e4544']
            self.eq(wflow, {'name': 'baz', 'desc': 'this is the real baz desc'})

            # nodocs
            nodocspath = s_common.genpath(core.dirn, 'testpkg_nodocs.json')
            argv = ('--no-docs', '--save', nodocspath, ymlpath)

            await s_genpkg.main(argv)

            noddocs_pdef = s_common.yamlload(nodocspath)

            self.eq(noddocs_pdef['name'], 'testpkg')
            self.eq(noddocs_pdef['docs'][0]['title'], 'Foo Bar')
            self.eq(noddocs_pdef['docs'][0]['content'], '')

            # No push, no save:  nothing to do
            argv = (ymlpath,)
            retn = await s_genpkg.main(argv)
            self.eq(1, retn)

            # Invalid:  save with pre-made file
            argv = ('--no-build', '--save', savepath, savepath)
            retn = await s_genpkg.main(argv)
            self.eq(1, retn)

            # Push a premade yaml
            argv = ('--push', url, '--no-build', yamlpath)
            retn = await s_genpkg.main(argv)
            self.eq(0, retn)

            # Push a premade json
            argv = ('--no-build', '--push', url, savepath)
            retn = await s_genpkg.main(argv)
            self.eq(0, retn)

            # Cannot push a file that does not exist
            argv = ('--push', url, '--no-build', newppath)
            retn = await s_genpkg.main(argv)
            self.eq(1, retn)

    def test_tools_tryloadpkg(self):
        ymlpath = s_common.genpath(dirname, 'files', 'stormpkg', 'nosuchfile.yaml')
        pkg = s_genpkg.tryLoadPkgProto(ymlpath)
        # Ensure it ran the fallback to do_docs=False
        self.eq(pkg.get('docs'), [{'title': 'newp', 'path': 'docs/newp.md', 'content': ''}])

    def test_files(self):
        assets = s_files.getAssets()
        self.isin('test.dat', assets)

        s = s_files.getAssetStr('stormmod/common')
        self.isinstance(s, str)

        self.raises(ValueError, s_files.getAssetPath, 'newp.bin')
        self.raises(ValueError, s_files.getAssetPath,
                    '../../../../../../../../../etc/passwd')
