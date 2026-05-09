import sys, io, joblib, numpy as np, re
from urllib.parse import urlparse

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

model = joblib.load('phishing_model.pkl')

def extract_features(url):
    features = []
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path   = parsed.path.lower()
        features.append(1 if parsed.scheme == 'https' else 0)
        features.append(len(url))
        features.append(domain.count('.'))
        features.append(domain.count('-'))
        features.append(domain.count('_'))
        features.append(1 if re.search(r'\d', domain) else 0)
        features.append(len(domain))
        features.append(len(path))
        features.append(1 if '@' in url else 0)
        features.append(1 if '//' in path else 0)
        features.append(url.count('?'))
        features.append(url.count('&'))
        features.append(1 if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0)
        suspicious_tlds = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.work']
        features.append(1 if any(domain.endswith(t) for t in suspicious_tlds) else 0)
        features.append(1 if not all(ord(c) < 128 for c in domain) else 0)
        features.extend([0] * 15)
    except Exception as e:
        features.extend([0] * (30 - len(features)))
    while len(features) < 30:
        features.append(0)
    return np.array(features[:30])

test_urls = [
    # Legitimate
    ('https://google.com', 'LEGIT'),
    ('https://microsoft.com', 'LEGIT'),
    ('https://apple.com', 'LEGIT'),
    ('https://amazon.com', 'LEGIT'),
    ('https://facebook.com', 'LEGIT'),
    ('https://twitter.com', 'LEGIT'),
    ('https://instagram.com', 'LEGIT'),
    ('https://linkedin.com', 'LEGIT'),
    ('https://netflix.com', 'LEGIT'),
    ('https://spotify.com', 'LEGIT'),
    ('https://adobe.com', 'LEGIT'),
    ('https://salesforce.com', 'LEGIT'),
    ('https://oracle.com', 'LEGIT'),
    ('https://ibm.com', 'LEGIT'),
    ('https://intel.com', 'LEGIT'),
    ('https://ebay.com', 'LEGIT'),
    ('https://walmart.com', 'LEGIT'),
    ('https://target.com', 'LEGIT'),
    ('https://bestbuy.com', 'LEGIT'),
    ('https://etsy.com', 'LEGIT'),
    ('https://aliexpress.com', 'LEGIT'),
    ('https://shopify.com', 'LEGIT'),
    ('https://paypal.com', 'LEGIT'),
    ('https://chase.com', 'LEGIT'),
    ('https://bankofamerica.com', 'LEGIT'),
    ('https://wellsfargo.com', 'LEGIT'),
    ('https://americanexpress.com', 'LEGIT'),
    ('https://capitalone.com', 'LEGIT'),
    ('https://schwab.com', 'LEGIT'),
    ('https://cnn.com', 'LEGIT'),
    ('https://bbc.com', 'LEGIT'),
    ('https://nytimes.com', 'LEGIT'),
    ('https://theguardian.com', 'LEGIT'),
    ('https://reuters.com', 'LEGIT'),
    ('https://bloomberg.com', 'LEGIT'),
    ('https://forbes.com', 'LEGIT'),
    ('https://wikipedia.org', 'LEGIT'),
    ('https://mit.edu', 'LEGIT'),
    ('https://stanford.edu', 'LEGIT'),
    ('https://harvard.edu', 'LEGIT'),
    ('https://coursera.org', 'LEGIT'),
    ('https://khanacademy.org', 'LEGIT'),
    ('https://edx.org', 'LEGIT'),
    ('https://gov.uk', 'LEGIT'),
    ('https://usa.gov', 'LEGIT'),
    ('https://irs.gov', 'LEGIT'),
    ('https://usps.com', 'LEGIT'),
    ('https://github.com', 'LEGIT'),
    ('https://stackoverflow.com', 'LEGIT'),
    ('https://gitlab.com', 'LEGIT'),
    ('https://docker.com', 'LEGIT'),
    ('https://npmjs.com', 'LEGIT'),
    ('https://pypi.org', 'LEGIT'),
    ('https://aws.amazon.com', 'LEGIT'),
    ('https://azure.microsoft.com', 'LEGIT'),
    ('https://cloud.google.com', 'LEGIT'),
    ('https://heroku.com', 'LEGIT'),
    ('https://digitalocean.com', 'LEGIT'),
    ('https://zoom.us', 'LEGIT'),
    ('https://slack.com', 'LEGIT'),
    ('https://discord.com', 'LEGIT'),
    ('https://telegram.org', 'LEGIT'),
    ('https://whatsapp.com', 'LEGIT'),
    ('https://booking.com', 'LEGIT'),
    ('https://airbnb.com', 'LEGIT'),
    ('https://expedia.com', 'LEGIT'),
    ('https://tripadvisor.com', 'LEGIT'),
    ('https://youtube.com', 'LEGIT'),
    ('https://twitch.tv', 'LEGIT'),
    ('https://reddit.com', 'LEGIT'),
    ('https://pinterest.com', 'LEGIT'),
    ('https://tumblr.com', 'LEGIT'),
    ('https://webmd.com', 'LEGIT'),
    ('https://mayoclinic.org', 'LEGIT'),
    ('https://cdc.gov', 'LEGIT'),
    ('https://nih.gov', 'LEGIT'),
    ('https://dropbox.com', 'LEGIT'),
    ('https://notion.so', 'LEGIT'),
    ('https://trello.com', 'LEGIT'),
    ('https://asana.com', 'LEGIT'),
    ('https://evernote.com', 'LEGIT'),

    # Phishing
    ('https://easybank.vercel.app/', 'PHISHING'),
    ('https://dotnotblock-pfwzl61nwt.edgeone.app/', 'PHISHING'),
    ('http://whatsapplnfo.blogspot.com/?m=1', 'PHISHING'),
    ('http://pub-e7b64c658d8647888de66296dd65df4a.r2.dev/index.html', 'PHISHING'),
    ('https://q-r.to/bgfw9x', 'PHISHING'),
    ('http://secure.rastrear-paquetes-perdidos.mx/s/63BZGFSVBWSFCDX7Y9/584dd8/90eab167-7429-489f-99f6-ce86e8d0d81a', 'PHISHING'),
    ('https://xayman0009-cmyk.github.io/netflix-clone', 'PHISHING'),
    ('https://roblox.com.py/users/716626416/profile', 'PHISHING'),
    ('http://tr.galabet-2026-online.vip/', 'PHISHING'),
    ('https://booking-clone-beta.vercel.app/', 'PHISHING'),
    ('https://sigafreeflowdigital.it.com/', 'PHISHING'),
    ('http://adobe.authorised-support.com/login/CFf9aOkGWsy07i0s-EFU1vq3ThKYAREV3UkY=9CA==/dfeyClRYnL-1gpHBCdJsrrxWw6mYBr3P/', 'PHISHING'),
    ('https://easy-bank-theta.vercel.app/', 'PHISHING'),
    ('https://amazon-clone-ruby-eight.vercel.app/', 'PHISHING'),
    ('https://www.lifeatspotify.com/being-here/work-from-anywhere', 'PHISHING'),
    ('http://www.udidi.weebly.com/', 'PHISHING'),
    ('http://pub-d5295b49d0874fe9b32ead8cf37d2390.r2.dev/index.html', 'PHISHING'),
    ('https://muddy-credit-c341.cdo-labs-fair-hacker.workers.dev/payments', 'PHISHING'),
    ('http://httpss-roblox.co/users/1721859/profile', 'PHISHING'),
    ('https://roblox.com.ge/games/79476121112919/Room-of-UwU-Furry?privateServerLinkCode=29499294128210761040731839221966', 'PHISHING'),
    ('https://roblox.com.ly/games/109983668079237/FUSE-Steal-a-Brainrot?privateServerLinkCode=40614205661476276159951188189478', 'PHISHING'),
    ('http://kevindew.github.io/govuk-content-history-user-research/pay-stamp-duty-land-tax', 'PHISHING'),
    ('https://roblox.com.ge/games/3623096087/Muscle-Legends?privateServerLinkCode=86502182669851378681200621959044', 'PHISHING'),
    ('https://sho-shop.vercel.app/', 'PHISHING'),
    ('https://l.ead.me/bgfnmP', 'PHISHING'),
    ('http://roblox.com.ge/communities/5773131333/', 'PHISHING'),
    ('https://ssl.myonlinepictureshare.com/s/63BZGFSVBWSFCDX7Y9/584dd8/90eab167-7429-489f-99f6-ce86e8d0d81a', 'PHISHING'),
    ('https://associazionegenia.it/wp-includes/IXR/json/json/import/', 'PHISHING'),
    ('http://www.metamask-wagmi-demo.vercel.app/', 'PHISHING'),
    ('https://easybank-landing-page-rabwinter.vercel.app/', 'PHISHING'),
    ('http://tr.ngsbahis-hemenboss.vip/', 'PHISHING'),
    ('https://qrco.de/bgfwyC', 'PHISHING'),
    ('https://roblox.mq/games/121864768012064/UPD-Fish-It?privateServerLinkCode=49272682235683386856322976706847', 'PHISHING'),
    ('http://ipfs.io/ipfs/bafybeibo7ht7ythkoucqnhcd4lzr5szfwtrptccysxsiviodgktm7moe7m', 'PHISHING'),
    ('http://f.digitalmaillane.com/igit/4/brhpu71Rqtzebh1csmRph2Rrppl6RxkqRqogRzcRsRl', 'PHISHING'),
    ('https://amazon-clone-mocha-nine.vercel.app/', 'PHISHING'),
    ('https://uphoald-logginus.godaddysites.com/', 'PHISHING'),
    ('https://j0ckk2pj-itrust-com.vercel.app/', 'PHISHING'),
    ('https://metamask-wagmi-demo.vercel.app/', 'PHISHING'),
    ('http://www.is.gd/Tls4fz/', 'PHISHING'),
    ('http://costumesnsfw.com/s/63BZGFSVBWSFCDX7Y9/584dd8/90eab167-7429-489f-99f6-ce86e8d0d81a', 'PHISHING'),
    ('http://satelliteoffice-1742766257.teamtailor.com/connect', 'PHISHING'),
    ('https://suncoast-dev-git-scups-131-suncoast-credit-union.vercel.app/Excessive-or-Luxury-Expenditure-Policy', 'PHISHING'),
    ('https://www.trezorsuite-docs.vercel.app/', 'PHISHING'),
    ('https://www.upho0ld-logiinus.godaddysites.com/', 'PHISHING'),
    ('https://itzz-07.github.io/Happy-Birthday-/', 'PHISHING'),
    ('https://94050105.xyz/', 'PHISHING'),
    ('https://parking-qf.cn/i', 'PHISHING'),
    ('https://m.08a5157.com/wp-admin/.wp-languages/.wjpl95qv_mlr.php/', 'PHISHING'),
    ('https://www.robiox.com.py/users/275772279564/profile', 'PHISHING'),
    ('https://fa-etbx-saasfaprod1.fa.ocs.oraclecloud.com/hcmUI/CandidateExperience/en/sites/nfcu/job/28120', 'PHISHING'),
    ('http://www.uphold-logins.blogspot.com/', 'PHISHING'),
    ('https://suncoast-dev-git-scups-131-suncoast-credit-union.vercel.app/', 'PHISHING'),
    ('https://qrco.de/bgfnmP', 'PHISHING'),
    ('https://wellsfrargo-server.joedesa.com/', 'PHISHING'),
    ('https://www-roblox.co/share?code=75438105480072894966428627606673&type=Profile&source=ProfileShare&gameid=16732694052', 'PHISHING'),
    ('https://anshuman-sahu-dev.github.io/Netflix-Clone/', 'PHISHING'),
    ('https://roblox.com.ge/communities/1005539398/', 'PHISHING'),
    ('https://roblox.mq/users/1735192530/profile', 'PHISHING'),
    ('https://www.5mp.eu/fajlok2/grupovisabeira/index_www.5mp.eu_.html', 'PHISHING'),
    ('https://garantiadecompra.com/', 'PHISHING'),
    ('https://digitaldebito.com/', 'PHISHING'),
    ('http://baskets-mandatory-paradise-cases.trycloudflare.com/457f46787bfe10de7a192146d29524971b3ef18a3c30dd917d5dbd038d97766e/networksolutions/index.html', 'PHISHING'),
    ('http://ehay-uk-login-secures-rcrrzwzs.name2brands.com/.dev/ehay-uk-login-secures-rcrrzwzs.name2brands.com', 'PHISHING'),
    ('https://bafybeiaynlkvzpw5c3tfhkh7hq5wsqbfce7cvue6wfpa2nozxon5fbdfru.ipfs.dweb.link/', 'PHISHING'),
    ('https://mayankkumarw201-afk.github.io/netflix/', 'PHISHING'),
    ('https://notifyhubss.net/y0abc8457cd6f94eebl9b7b3ebc878b2fb10.html/', 'PHISHING'),
    ('https://jexi-bank.vercel.app/', 'PHISHING'),
    ('http://bietmaertlogin.webflow.io/', 'PHISHING'),
    ('https://amazon-clone-part-1.vercel.app/', 'PHISHING'),
    ('https://spotifylife.dpdns.org/de/lifeatspotify', 'PHISHING'),
    ('https://crypto-currency-landingpage-clone.vercel.app/', 'PHISHING'),
    ('https://www.robiox.com.py/games/77747658251236/JJK-Update-Sailor-Piece?privateServerLinkCode=654816135886556347247621249897', 'PHISHING'),
    ('https://m.08a5157.com/', 'PHISHING'),
    ('https://whatsapp-clone-desktop.vercel.app/', 'PHISHING'),
    ('https://roblox.com.py/communities/7309647847/', 'PHISHING'),
    ('https://easy-bank-tutorial.netlify.app/', 'PHISHING'),
    ('http://ledger-security-online.com/', 'PHISHING'),
    ('http://www.docusigndocs2026.weebly.com/', 'PHISHING'),
    ('https://www.robiox.com.py/users/186565331515/profile', 'PHISHING'),
    ('https://applelocalizar.com/', 'PHISHING'),
    ('http://f.digitalmaillane.com/igit/4/6wxqj5jRujrph1kvb5Rr7mRtehketRv5aR87zRivRbR4', 'PHISHING'),
    ('http://roblox.com.ge/users/3964727128/profile', 'PHISHING'),
    ('https://trezorsuite-docs.vercel.app/', 'PHISHING'),
    ('https://q-r.to/bgfnmP', 'PHISHING'),
    ('http://lnstagramcom572.github.io/Instagram/', 'PHISHING'),
    ('https://l.ead.me/bgftyT', 'PHISHING'),
    ('https://edgaralvarado24.github.io/amazon-website/', 'PHISHING'),
    ('https://roblox.com.ge/users/4091258055/profile', 'PHISHING'),
    ('https://biancacastrogomes1769819760631.2292159.meusitehostgator.com.br/benth/nicht/login.php', 'PHISHING'),
    ('https://shortlink.st/f-bok4ox', 'PHISHING'),
    ('https://q-r.to/bgftyT', 'PHISHING'),
    ('https://roblox.com.ge/users/4463654174/profile', 'PHISHING'),
    ('https://q-r.to/bgfwyC', 'PHISHING'),
    ('http://www.facebookcolorvisitor.blogspot.com/', 'PHISHING'),
    ('https://airbnb-clone-iota-five.vercel.app/', 'PHISHING'),
    ('http://adobe.authorised-support.com/login/CFf9aOkGWsy07i0s-EFU1vq3ThKYAREV3UkY=9CA==9WF1WW1xmVVZeUFc=/dfeyClRYnL-1gpHBCdJsrrxWw6mYBr3P/', 'PHISHING'),
    ('https://connect.secure.wellsfrargo-server.joedesa.com/', 'PHISHING'),
    ('http://notifyhubss.net/y0abc8457cd6f94eebl9b7b3ebc878b2fb10.html', 'PHISHING'),
    ('https://uphold-logins.blogspot.com/', 'PHISHING'),
]

print('=' * 85)
print('   PHISHING DETECTION - AI MODEL TEST')
print('=' * 85)
print(f"   {'URL':<60} {'ACTUAL':<8} {'AI PRED':<8} {'CONF'}")
print('-' * 85)

correct = 0
for url, actual in test_urls:
    feat = extract_features(url).reshape(1, -1)
    pred = model.predict(feat)[0]
    conf = model.predict_proba(feat)[0]
    
    label = 'PHISHING' if pred == 1 else 'LEGIT'
    pct   = conf[1]*100 if pred == 1 else conf[0]*100
    
    short = (url[:57] + '..') if len(url) > 59 else url
    status = 'OK   ' if label == actual else 'WRONG'
    
    if label == actual:
        correct += 1
        
    print(f"   {short:<60} {actual:<8} {label:<8} {pct:.1f}% [{status}]")

print('=' * 85)
print(f"   Result: {correct}/{len(test_urls)} correct  ({correct/len(test_urls)*100:.1f}% accuracy)")
print('=' * 85)
