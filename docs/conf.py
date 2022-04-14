# -*- coding: utf-8 -*-
#
# Configuration file for the Sphinx documentation builder.
#
# This file does only contain a selection of the most common options. For a
# full list see the documentation:
# http://www.sphinx-doc.org/en/master/config

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys
sys.path.insert(0, os.path.abspath('..'))

import synapse


# -- Project information -----------------------------------------------------

project = 'Synapse'
copyright = '2021, The Vertex Project'
author = 'The Vertex Project'

# The short X.Y version
version = synapse.verstring
# The full version, including alpha/beta/rc tags
release = synapse.verstring


# -- General configuration ---------------------------------------------------

# If your documentation needs a minimal Sphinx version, state it here.
#
# needs_sphinx = '1.0'

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
    'notfound.extension',
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# The suffix(es) of source filenames.
# You can specify multiple suffix as a list of string:
#
# source_suffix = ['.rst', '.md']
source_suffix = '.rst'

# The master toctree document.
master_doc = 'index'

# The language for content autogenerated by Sphinx. Refer to documentation
# for a list of supported languages.
#
# This is also used if you do content translation via gettext catalogs.
# Usually you set "language" from the command line for these cases.
language = None

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = None


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_rtd_theme'

# Add custom logos
html_logo = "_static/logo.svg"

html_css_files = [
    'css/theme_overrides.css',
]

html_favicon = "_static/favicon.svg"

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
#
# html_theme_options = {}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# Custom sidebar templates, must be a dictionary that maps document names
# to template names.
#
# The default sidebars (for documents that don't match any pattern) are
# defined by theme itself.  Builtin themes are using these templates by
# default: ``['localtoc.html', 'relations.html', 'sourcelink.html',
# 'searchbox.html']``.
#
# html_sidebars = {}


# -- Options for HTMLHelp output ---------------------------------------------

# Output file base name for HTML help builder.
htmlhelp_basename = 'Synapsedoc'


# -- Options for LaTeX output ------------------------------------------------

latex_elements = {
    # The paper size ('letterpaper' or 'a4paper').
    #
    # 'papersize': 'letterpaper',

    # The font size ('10pt', '11pt' or '12pt').
    #
    # 'pointsize': '10pt',

    # Additional stuff for the LaTeX preamble.
    #
    # 'preamble': '',

    # Latex figure (float) alignment
    #
    # 'figure_align': 'htbp',
}

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title,
#  author, documentclass [howto, manual, or own class]).
latex_documents = [
    (master_doc, 'Synapse.tex', 'Synapse Documentation',
     'The Vertex Project', 'manual'),
]


# -- Options for manual page output ------------------------------------------

# One entry per manual page. List of tuples
# (source start file, name, description, authors, manual section).
man_pages = [
    (master_doc, 'synapse', 'Synapse Documentation',
     [author], 1)
]


# -- Options for Texinfo output ----------------------------------------------

# Grouping the document tree into Texinfo files. List of tuples
# (source start file, target name, title, author,
#  dir menu entry, description, category)
texinfo_documents = [
    (master_doc, 'Synapse', 'Synapse Documentation',
     author, 'Synapse', 'One line description of project.',
     'Miscellaneous'),
]


# -- Options for Epub output -------------------------------------------------

# Bibliographic Dublin Core info.
epub_title = project

# The unique identifier of the text. This can be a ISBN number
# or the project homepage.
#
# epub_identifier = ''

# A unique identification for the text.
#
# epub_uid = ''

# A list of files that should not be packed into the epub file.
epub_exclude_files = ['search.html']


# -- Extension configuration -------------------------------------------------

# Our magic
def run_apidoc(_):
    from sphinx.ext.apidoc import main

    args = ['-M', '--no-toc', '-o', './synapse/autodocs', '../synapse', ]
    ignores = ['../synapse/tests', '../synapse/vendor']
    args.extend(ignores)
    main(args)

def run_modeldoc(_):
    import synapse
    import subprocess
    abssynf = os.path.abspath(synapse.__file__)
    synbd = os.path.split(abssynf)[0]  # Split off __init__
    synpd = os.path.split(synbd)[0]  # split off the synapse module directory
    args = ['python', '-m', 'synapse.tools.autodoc', '--doc-model',
            '--savedir', './docs/synapse/autodocs']
    subprocess.run(args, cwd=synpd)

def run_confdocs(_):
    import synapse
    import subprocess
    abssynf = os.path.abspath(synapse.__file__)
    synbd = os.path.split(abssynf)[0]  # Split off __init__
    synpd = os.path.split(synbd)[0]  # split off the synapse module directory
    baseargs = ['python', '-m', 'synapse.tools.autodoc', '--savedir',
                './docs/synapse/autodocs', '--doc-conf']
    ctors = ('synapse.axon.Axon',
             'synapse.cortex.Cortex',
             'synapse.lib.aha.AhaCell',
             'synapse.lib.jsonstor.JsonStorCell',
             'synapse.cryotank.CryoCell',
             )
    for ctor in ctors:
        args = baseargs.copy()
        args.append(ctor)
        subprocess.run(args, cwd=synpd)

def run_stormtypes(_):
    import synapse
    import subprocess
    abssynf = os.path.abspath(synapse.__file__)
    synbd = os.path.split(abssynf)[0]  # Split off __init__
    synpd = os.path.split(synbd)[0]  # split off the synapse module directory
    args = ['python', '-m', 'synapse.tools.autodoc', '--doc-stormtypes',
            '--savedir', './docs/synapse/autodocs']
    r = subprocess.run(args, cwd=synpd)
    assert r.returncode == 0, f'Failed to convert stormtypes.'

def convert_ipynb(_):
    import synapse.common as s_common
    import nbconvert.nbconvertapp as nba
    cwd = os.getcwd()
    for fdir, dirs, fns in os.walk(cwd):
        if '.ipynb_checkpoints' in dirs:
            dirs.remove('.ipynb_checkpoints')
        for fn in fns:
            if fn.endswith('.ipynb'):
                # if 'httpapi' not in fn:
                #     continue
                tick = s_common.now()
                fp = os.path.join(fdir, fn)
                args = ['--execute', '--template', './vertex.tpl', '--to', 'rst', fp]
                nba.main(args)
                tock = s_common.now()
                took = (tock - tick) / 1000
                print(f'convert_ipynb: Notebook {fn} execution took {took} seconds.')


def convert_rstorm(_):
    import subprocess

    import synapse
    import synapse.common as s_common
    abssynf = os.path.abspath(synapse.__file__)
    synbd = os.path.split(abssynf)[0]  # Split off __init__
    synpd = os.path.split(synbd)[0]  # split off the synapse module directory
    env = {**os.environ, 'SYN_LOG_LEVEL': 'DEBUG'}

    cwd = os.getcwd()
    for fdir, dirs, fns in os.walk(cwd):
        for fn in fns:
            if fn.endswith('.rstorm'):

                oname = fn.rsplit('.', 1)[0]
                oname = oname + '.rst'
                sfile = os.path.join(fdir, fn)
                ofile = os.path.join(fdir, oname)

                tick = s_common.now()

                args = ['python', '-m', 'synapse.tools.rstorm', '--save', ofile, sfile]
                r = subprocess.run(args, cwd=synpd, env=env)
                assert r.returncode == 0, f'Failed to convert {sfile}'

                tock = s_common.now()
                took = (tock - tick) / 1000
                print(f'convert_rstorm: Rstorm {fn} execution took {took} seconds.')

def setup(app):
    app.connect('builder-inited', run_apidoc)
    app.connect('builder-inited', run_modeldoc)
    app.connect('builder-inited', run_confdocs)
    app.connect('builder-inited', convert_ipynb)
    app.connect('builder-inited', convert_rstorm)
    app.connect('builder-inited', run_stormtypes)
