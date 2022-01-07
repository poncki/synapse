import logging
import collections

import idna
import regex
import unicodedata

import synapse.data as s_data

import synapse.lib.crypto.coin as s_coin


logger = logging.getLogger(__name__)

tldlist = list(s_data.get('iana.tlds'))
tldlist.extend([
    'bit',
    'onion',
])

tldlist.sort(key=lambda x: len(x))
tldlist.reverse()

tldcat = '|'.join(tldlist)
fqdn_re = regex.compile(r'((?:[a-z0-9_-]{1,63}\.){1,10}(?:%s))' % tldcat)

idna_disallowed = r'\$+<->\^`|~\u00A8\u00AF\u00B4\u00B8\u02D8-\u02DD\u037A\u0384\u0385\u1FBD\u1FBF-\u1FC1\u1FCD-\u1FCF\u1FDD-\u1FDF\u1FED-\u1FEF\u1FFD\u1FFE\u207A\u207C\u208A\u208C\u2100\u2101\u2105\u2106\u2474-\u24B5\u2A74-\u2A76\u2FF0-\u2FFB\u309B\u309C\u3200-\u321E\u3220-\u3243\u33C2\u33C7\u33D8\uFB29\uFC5E-\uFC63\uFDFA\uFDFB\uFE62\uFE64-\uFE66\uFE69\uFE70\uFE72\uFE74\uFE76\uFE78\uFE7A\uFE7C\uFE7E\uFF04\uFF0B\uFF1C-\uFF1E\uFF3E\uFF40\uFF5C\uFF5E\uFFE3\uFFFC\uFFFD\U0001F100-\U0001F10A\U0001F110-\U0001F129\U000E0100-\U000E01EF'

udots = regex.compile(r'[\u3002\uff0e\uff61]')

# avoid thread safety issues due to uts46_remap() importing uts46data
idna.encode('init', uts46=True)

FANGS = {
    'hxxp:': 'http:',
    'hxxps:': 'https:',
    'hxxp[:]': 'http:',
    'hxxps[:]': 'https:',
    'hxxp(:)': 'http:',
    'hxxps(:)': 'https:',
    '[.]': '.',
    '[．]': '．',
    '[。]': '。',
    '[｡]': '｡',
    '(.)': '.',
    '(．)': '．',
    '(。)': '。',
    '(｡)': '｡',
    '[:]': ':',
    'fxp': 'ftp',
    'fxps': 'ftps',
    '[at]': '@',
    '[@]': '@',
}

inverse_prefixs = {
    '[': ']',
    '<': '>',
    '{': '}',
    '(': ')',
}


def fqdn_prefix_check(match: regex.Match):
    mnfo = match.groupdict()
    valu = mnfo.get('valu')
    prefix = mnfo.get('prefix')
    cbfo = {}
    if prefix is not None:
        new_valu = valu.rstrip(inverse_prefixs.get(prefix))
        if new_valu != valu:
            valu = new_valu
            cbfo['raw_valu'] = valu
    return valu, cbfo

def fqdn_check(match: regex.Match):
    mnfo = match.groupdict()
    valu = mnfo.get('valu')

    nval = unicodedata.normalize('NFKC', valu)
    nval = regex.sub(udots, '.', nval)
    nval = nval.strip().strip('.')

    try:
        idna.encode(nval, uts46=True).decode('utf8')
    except idna.IDNAError:
        try:
            nval.encode('idna').decode('utf8').lower()
        except UnicodeError:
            return None, {}
    return valu, {}

re_fang = regex.compile("|".join(map(regex.escape, FANGS.keys())), regex.IGNORECASE)

# these must be ordered from most specific to least specific to allow first=True to work
scrape_types = [  # type: ignore
    ('inet:url', r'(?P<prefix>[\\{<\(\[]?)(?P<valu>[a-zA-Z][a-zA-Z0-9]*://(?(?=[,.]+[ \'\"\t\n\r\f\v])|[^ \'\"\t\n\r\f\v])+)',
     {'callback': fqdn_prefix_check}),
    ('inet:email', r'(?=(?:[^a-z0-9_.+-]|^)(?P<valu>[a-z0-9_\.\-+]{1,256}@(?:[a-z0-9_-]{1,63}\.){1,10}(?:%s))(?:[^a-z0-9_.-]|[.\s]|$))' % tldcat, {}),
    ('inet:server', r'(?P<valu>(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):[0-9]{1,5})', {}),
    ('inet:ipv4', r'(?P<valu>(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))', {}),
    ('inet:fqdn', r'(?=(?:[^\p{L}\p{M}\p{N}\p{S}\u3002\uff0e\uff61_.-]|^|[' + idna_disallowed + '])(?P<valu>(?:((?![' + idna_disallowed + r'])[\p{L}\p{M}\p{N}\p{S}_-]){1,63}[\u3002\uff0e\uff61\.]){1,10}(?:' + tldcat + r'))(?:[^\p{L}\p{M}\p{N}\p{S}\u3002\uff0e\uff61_.-]|[\u3002\uff0e\uff61.]([\p{Z}\p{Cc}]|$)|$|[' + idna_disallowed + r']))', {'callback': fqdn_check}),
    ('hash:md5', r'(?=(?:[^A-Za-z0-9]|^)(?P<valu>[A-Fa-f0-9]{32})(?:[^A-Za-z0-9]|$))', {}),
    ('hash:sha1', r'(?=(?:[^A-Za-z0-9]|^)(?P<valu>[A-Fa-f0-9]{40})(?:[^A-Za-z0-9]|$))', {}),
    ('hash:sha256', r'(?=(?:[^A-Za-z0-9]|^)(?P<valu>[A-Fa-f0-9]{64})(?:[^A-Za-z0-9]|$))', {}),
    ('it:sec:cve', r'(?:[^a-z0-9]|^)(?P<valu>CVE-[0-9]{4}-[0-9]{4,})(?:[^a-z0-9]|$)', {}),
    ('crypto:currency:address', r'(?=(?:[^A-Za-z0-9]|^)(?P<valu>[1][a-zA-HJ-NP-Z0-9]{25,39})(?:[^A-Za-z0-9]|$))',
     {'callback': s_coin.btc_base58_check}),
    ('crypto:currency:address', r'(?=(?:[^A-Za-z0-9]|^)(?P<valu>3[a-zA-HJ-NP-Z0-9]{33})(?:[^A-Za-z0-9]|$))',
     {'callback': s_coin.btc_base58_check}),
    ('crypto:currency:address', r'(?=(?:[^A-Za-z0-9]|^)(?P<valu>(bc|bcrt|tb)1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{3,71})(?:[^A-Za-z0-9]|$))',
     {'callback': s_coin.btc_bech32_check}),
    ('crypto:currency:address', r'(?=(?:[^A-Za-z0-9]|^)(?P<valu>0x[A-Fa-f0-9]{40})(?:[^A-Za-z0-9]|$))',
     {'callback': s_coin.eth_check}),
    ('crypto:currency:address', r'(?=(?:[^A-Za-z0-9]|^)(?P<valu>(bitcoincash|bchtest):[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{42})(?:[^A-Za-z0-9]|$))',
     {'callback': s_coin.bch_check}),
    ('crypto:currency:address', r'(?=(?:[^A-Za-z0-9]|^)(?P<valu>[xr][a-zA-HJ-NP-Z0-9]{25,46})(?:[^A-Za-z0-9]|$))',
     {'callback': s_coin.xrp_check}),
    ('crypto:currency:address', r'(?=(?:[^A-Za-z0-9]|^)(?P<valu>[1a-z][a-zA-HJ-NP-Z0-9]{46,47})(?:[^A-Za-z0-9]|$))',
     {'callback': s_coin.substrate_check}),
    ('crypto:currency:address', r'(?=(?:[^A-Za-z0-9]|^)(?P<valu>(DdzFF|Ae2td)[a-zA-HJ-NP-Z0-9]{54,99})(?:[^A-Za-z0-9]|$))',
     {'callback': s_coin.cardano_byron_check}),
    ('crypto:currency:address', r'(?=(?:[^A-Za-z0-9]|^)(?P<valu>addr1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{53})(?:[^A-Za-z0-9]|$))',
     {'callback': s_coin.cardano_shelly_check}),
]

_regexes = collections.defaultdict(list)
for (name, rule, opts) in scrape_types:
    blob = (regex.compile(rule, regex.IGNORECASE), opts)
    _regexes[name].append(blob)

def getPtypes():
    '''
    Get a list of ptypes recognized by the scrape APIs.

    Returns:
        list: A list of ptype values.
    '''
    return sorted(_regexes.keys())

def refang_text(txt):
    '''
    Remove address de-fanging in text blobs, .e.g. example[.]com to example.com

    Matches to keys in FANGS is case-insensitive, but replacement will always be
    with the lowercase version of the re-fanged value.
    For example, HXXP://FOO.COM will be returned as http://FOO.COM

    Returns:
        (str): Re-fanged text blob
    '''
    return re_fang.sub(lambda match: FANGS[match.group(0).lower()], txt)

def scrape(text, ptype=None, refang=True, first=False):
    '''
    Scrape types from a blob of text and return node tuples.

    Args:
        text (str): Text to scrape.
        ptype (str): Optional ptype to scrape. If present, only scrape items which match the provided type.
        refang (bool): Whether to remove de-fanging schemes from text before scraping.
        first (bool): If true, only yield the first item scraped.

    Returns:
        (str, object): Yield tuples of node ndef values.
    '''

    for info in contextScrape(text, ptype=ptype, refang=refang, first=first):
        yield info.get('form'), info.get('valu')

def contextScrape(text, ptype=None, refang=True, first=False):
    '''
    Scrape types from a blob of text and return context information.

    Args:
        text (str): Text to scrape.
        ptype (str): Optional ptype to scrape. If present, only scrape items which match the provided type.
        refang (bool): Whether to remove de-fanging schemes from text before scraping.
        first (bool): If true, only yield the first item scraped.

    Returns:
        (dict): yield dictionaries of scrape information.
    '''

    if refang:
        text = refang_text(text)

    for ruletype, blobs in _regexes.items():
        if ptype and ptype != ruletype:
            continue

        for (regx, opts) in blobs:

            for info in genMatches(text, regx, ruletype, opts):
                yield info

                if first:
                    return

def genMatches(text: str, regx: regex.Regex, form: str, opts: dict):
    '''
    Generate regular expression matches for a blob of text.

    Args:
        text (str): The t
        regx (regex.Regex): A compiled regex object. The regex must contained a named match for ``valu``.
        form (str): The form XXX ???
        opts (dict): XXX

    Yields:
        dict: A dictionary of match results.
    '''
    cb = opts.get('callback')

    for valu in regx.finditer(text):  # type: regex.Match
        raw_span = valu.span('valu')
        raw_valu = valu.group('valu')

        info = {
            'form': form,
            'raw_valu': raw_valu,
            'offset': raw_span[0]
        }

        if cb:
            # CB is expected to return a tufo of <new valu, info>
            valu, cbfo = cb(valu)
            if valu is None:
                continue
            # Smash cbfo into our info dict
            info.update(**cbfo)
        else:
            valu = raw_valu

        info['valu'] = valu

        yield info
