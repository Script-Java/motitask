import requests

def get_quote():
    req = requests.get('https://zenquotes.io/api/today')
    res = req.json()
    quote = res[0]["q"]
    author = res[0]["a"]
    return [quote, author]
