import requests
from bs4 import BeautifulSoup

class GoogleNewsScraper:
    def __init__(self):
        self.base_url = 'https://news.google.com/search?q='

    def scrape(self, query):
        query = query.replace(' ', '%20')  # Replace spaces with %20 for the URL
        url = self.base_url + query

        response = requests.get(url)
        response.raise_for_status()  # Raise an exception if request was unsuccessful

        soup = BeautifulSoup(response.text, 'html.parser')
        articles = soup.select('article')

        news_list = []
        for article in articles:
            title = article.select_one('h3').text
            source = article.select_one('.SFllF > span:first-child').text
            link = article.find('a')['href']
            news_list.append({'title': title, 'source': source, 'link': link})

        return news_list
