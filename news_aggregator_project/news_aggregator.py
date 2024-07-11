from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymongo import MongoClient, errors
from bson.objectid import ObjectId
from scrapy.crawler import CrawlerRunner
from scrapy.utils.log import configure_logging
from twisted.internet import reactor, task
import bcrypt
import os
import requests
import json
import logging
import threading
import time
from oauthlib.oauth2 import WebApplicationClient
import scrapy
from urllib.parse import urljoin
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('news_scraper')

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
db = client['news_aggregator']
users_collection = db['users']
news_collection = db['news']

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_register'

class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

@login_manager.user_loader
def load_user(user_id):
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if user:
        return User(user_id)
    return None

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'verakatsikas@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'VeraKatsikas2468!'  # Replace with your email password
app.config['MAIL_DEFAULT_SENDER'] = 'verakatsikas@gmail.com'  # Replace with your email

mail = Mail(app)

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/toggle_dark_mode', methods=['POST'])
def toggle_dark_mode():
    data = request.get_json()
    session['dark_mode'] = data['dark_mode']
    return jsonify(success=True)

@app.route('/login_register', methods=['GET', 'POST'])
def login_register():
    if request.method == 'POST':
        form_type = request.form['form_type']
        username = request.form['username']
        password = request.form['password']

        if form_type == 'login':
            user = users_collection.find_one({'username': username})
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
                login_user(User(user['_id']))
                return redirect(url_for('home'))
            flash('Invalid username or password', 'danger')

        elif form_type == 'register':
            email = request.form['email']
            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            users_collection.insert_one({'username': username, 'email': email, 'password': hashed_pw})
            flash('User registered successfully!', 'success')
            return redirect(url_for('login_register'))

    return render_template('auth.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login_register'))

@app.route('/profile')
@login_required
def profile():
    user = users_collection.find_one({"_id": ObjectId(current_user.id)})
    if user:
        return render_template('profile.html', user=user)
    return redirect(url_for('home'))

@app.route('/notifications')
@login_required
def notifications():
    user_notifications = []  # Replace with actual notification fetching logic
    return render_template('notifications.html', notifications=user_notifications)

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')


@app.route('/load_more')
def load_more():
    category = request.args.get('category')
    loaded = int(request.args.get('loaded', 0))
    per_page = 3

    articles = list(news_collection.find({"category": category}).sort("date_time", -1).skip(loaded).limit(per_page))
    has_more = len(articles) == per_page

    articles_data = []
    for article in articles:
        articles_data.append({
            "title": article["title"],
            "date_time": article["date_time"].strftime("%Y-%m-%d %H:%M:%S"),
            "category": article["category"],
            "photo_url": article["photo_url"],
            "summary": article["summary"],
            "_id": str(article["_id"])
        })

    return jsonify({"articles": articles_data, "has_more": has_more})

@app.route('/news')
def index():
    categories = news_collection.distinct("category")
    news_by_category = {category: list(news_collection.find({"category": category}).sort("date_time", -1)) for category in categories}
    return render_template('index.html', news_by_category=news_by_category)

@app.route('/news/<string:id>')
def news_detail(id):
    news_item = news_collection.find_one({"_id": ObjectId(id)})
    if news_item:
        return render_template('news_detail.html', news_item=news_item)
    return redirect(url_for('index'))

@app.route('/category/<string:category_name>')
def category_articles(category_name):
    page = request.args.get('page', 1, type=int)
    per_page = 6  # Number of articles per page
    articles = list(news_collection.find({"category": category_name}).sort("date_time", -1).skip((page - 1) * per_page).limit(per_page))
    total_articles = news_collection.count_documents({"category": category_name})
    has_prev = page > 1
    has_next = page * per_page < total_articles
    return render_template('category.html', category_name=category_name, articles=articles, page=page, has_prev=has_prev, has_next=has_next)

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '')
    search_results = []
    if query:
        search_filter = {
            "$or": [
                {"title": {"$regex": query, "$options": "i"}},
                {"summary": {"$regex": query, "$options": "i"}},
                {"main_text": {"$regex": query, "$options": "i"}}
            ]
        }
        cursor = news_collection.find(search_filter).sort("date_time", -1)
        search_results = list(cursor)

    return render_template('search.html', query=query, search_results=search_results)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if request.method == 'POST':
        title = request.form['title']
        date_time = request.form['date_time']
        category = request.form['category']
        url = request.form['url']
        photo_url = request.form['photo_url']
        summary = request.form['summary']
        tags = request.form['tags']
        main_text = request.form['main_text']

        news_item = {
            "title": title,
            "date_time": datetime.strptime(date_time, '%Y-%m-%dT%H:%M'),
            "category": category,
            "url": url,
            "photo_url": photo_url,
            "summary": summary,
            "tags": tags.split(','),  # Assuming tags are comma separated
            "main_text": main_text
        }

        news_collection.insert_one(news_item)
        flash('Article added successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('add.html')

@app.route('/<string:id>/edit', methods=['GET', 'POST'])
@login_required
def edit(id):
    news_item = news_collection.find_one({"_id": ObjectId(id)})

    if request.method == 'POST':
        updated_news_item = {
            "title": request.form['title'],
            "date_time": datetime.strptime(request.form['date_time'], '%Y-%m-%dT%H:%M'),
            "category": request.form['category'],
            "url": request.form['url'],
            "photo_url": request.form['photo_url'],
            "summary": request.form['summary'],
            "tags": request.form['tags'].split(','),  # Assuming tags are comma separated
            "main_text": request.form['main_text']
        }

        news_collection.update_one({"_id": ObjectId(id)}, {"$set": updated_news_item})
        flash('Article updated successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('edit.html', news_item=news_item)

@app.route('/<string:id>/delete', methods=['POST'])
@login_required
def delete(id):
    news_collection.delete_one({"_id": ObjectId(id)})
    flash('Article deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/scrape', methods=['GET', 'POST'])
@login_required
def scrape():
    if request.method == 'POST':
        threading.Thread(target=run_spiders).start()
        flash('Scraping in progress...', 'success')
        return redirect(url_for('index'))
    return render_template('scrape.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        
        try:
            msg = Message(subject=f"New Contact from {name}",
                          recipients=['recipient-email@gmail.com'],  # Replace with the recipient's email
                          body=f"Name: {name}\nEmail: {email}\n\nMessage:\n{message}")
            mail.send(msg)
            flash('Your message has been sent successfully!', 'success')
        except Exception as e:
            flash(f'An error occurred while sending your message: {str(e)}', 'danger')

        return redirect(url_for('contact'))
    
    return render_template('contact.html')

@app.route('/about')
def about():
    return render_template('about.html')

# Google login configuration
GOOGLE_CLIENT_ID = "YOUR_GOOGLE_CLIENT_ID"
GOOGLE_CLIENT_SECRET = "YOUR_GOOGLE_CLIENT_SECRET"
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

@app.route('/google_login')
def google_login():
    client = WebApplicationClient(GOOGLE_CLIENT_ID)
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]
    
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@app.route("/google_login/callback")
def google_login_callback():
    client = WebApplicationClient(GOOGLE_CLIENT_ID)
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    token_endpoint = google_provider_cfg["token_endpoint"]

    code = request.args.get("code")

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
        
        user = users_collection.find_one({"email": users_email})
        if not user:
            user = users_collection.insert_one({"username": users_name, "email": users_email, "profile_pic": picture})
        
        login_user(User(user['_id']))
        return redirect(url_for("home"))

    flash("User email not available or not verified by Google.", 'danger')
    return redirect(url_for("login_register"))

@app.route('/facebook_login')
def facebook_login():
    facebook_client_id = "YOUR_FACEBOOK_APP_ID"
    facebook_client_secret = "YOUR_FACEBOOK_APP_SECRET"
    fb_auth_uri = "https://www.facebook.com/v12.0/dialog/oauth"

    client = WebApplicationClient(facebook_client_id)
    request_uri = client.prepare_request_uri(
        fb_auth_uri,
        redirect_uri=request.base_url + "/callback",
        scope=["email"],
    )
    return redirect(request_uri)

@app.route("/facebook_login/callback")
def facebook_login_callback():
    facebook_client_id = "YOUR_FACEBOOK_APP_ID"
    facebook_client_secret = "YOUR_FACEBOOK_APP_SECRET"
    fb_token_uri = "https://graph.facebook.com/v12.0/oauth/access_token"
    fb_user_info = "https://graph.facebook.com/me?fields=id,name,email"

    code = request.args.get("code")
    client = WebApplicationClient(facebook_client_id)
    
    token_url, headers, body = client.prepare_token_request(
        fb_token_uri,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(facebook_client_id, facebook_client_secret),
    )

    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_response = requests.get(fb_user_info, headers={"Authorization": f"Bearer {token_response.json()['access_token']}"})

    if userinfo_response.json().get("email"):
        users_email = userinfo_response.json()["email"]
        users_name = userinfo_response.json()["name"]

        user = users_collection.find_one({"email": users_email})
        if not user:
            user = users_collection.insert_one({"username": users_name, "email": users_email})
        
        login_user(User(user['_id']))
        return redirect(url_for("home"))

    flash("User email not available or not verified by Facebook.", 'danger')
    return redirect(url_for("login_register"))

class NewsSpider(scrapy.Spider):
    name = 'news_spider'
    allowed_domains = ['naftemporiki.gr', 'kathimerini.gr']
    start_urls = [
        'https://www.naftemporiki.gr/newsroom',
        'https://www.kathimerini.gr/epikairothta'
    ]

    EXCLUDE_KEYWORDS = ['μέταλλα', 'χρυσός', 'ασήμι', 'ισοτιμίες', 'ομόλογα', 'αγορά', 'χρηματιστήριο', 'οικονομικά', 'επενδύσεις']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        try:
            self.client = MongoClient('mongodb://localhost:27017/')
            self.db = self.client['news_aggregator']
            self.collection = self.db['news']
            logger.info("Connected to MongoDB successfully.")
        except errors.ConnectionError as e:
            logger.error(f"Error connecting to MongoDB: {e}")

    def parse(self, response):
        domain = response.url.split('/')[2]
        logger.debug(f"Parsing domain: {domain}")
        if 'naftemporiki.gr' in domain:
            articles = response.css('div.item')  # Adjust according to Naftemporiki's structure
        else:
            articles = response.css('article')
        logger.debug(f"Found {len(articles)} articles on {domain}")
        for article in articles:
            link = article.css('a::attr(href)').get()
            if link:
                full_link = urljoin(response.url, link)
                logger.debug(f"Found article link: {full_link}")
                yield scrapy.Request(full_link, callback=self.parse_article, meta={'domain': domain})
                time.sleep(1)  # Add a sleep of 1 second between requests

        next_page = response.css('a.next::attr(href)').get() or response.css('a.pagination-next::attr(href)').get()
        if next_page:
            next_page = urljoin(response.url, next_page)
            logger.debug(f"Following pagination link: {next_page}")
            yield scrapy.Request(next_page, callback=self.parse)
            time.sleep(1)  # Add a sleep of 1 second between requests

    def parse_article(self, response):
        domain = response.meta['domain']
        try:
            title = response.css('h1::text').get() or response.css('h2::text').get()
            if title:
                title = title.strip()

            # Check if the title contains any of the exclude keywords
            if any(keyword.lower() in title.lower() for keyword in self.EXCLUDE_KEYWORDS):
                logger.info(f"Skipping article due to excluded keyword in title: {title}")
                return

            date_time_str = response.css('time::text').get() or response.css('.publish-date::text').get()
            if date_time_str:
                date_time_str = date_time_str.strip()
            date_time = self.parse_date(date_time_str)
            
            # Adjust selector for category based on correct CSS classes or XPath
            category = response.css('a.category::text').get()
            if not category:
                category = response.xpath("//meta[@property='article:section']/@content").get()
            if category:
                category = category.strip()
            else:
                category = 'Uncategorized'  # Default to English for "Uncategorized"

            photo_url = response.css('meta[property="og:image"]::attr(content)').get() or response.css('img::attr(src)').get()
            summary = response.css('div.summary::text').get() or response.css('meta[name="description"]::attr(content)').get()
            if summary:
                summary = summary.strip()

                # Check if the summary contains any of the exclude keywords
                if any(keyword.lower() in summary.lower() for keyword in self.EXCLUDE_KEYWORDS):
                    logger.info(f"Skipping article due to excluded keyword in summary: {summary}")
                    return

            tags = response.css('a.tag::text').getall()
            main_text_html = ''.join(response.css('div.article-body').getall())

            # Check if the main text contains any of the exclude keywords
            if any(keyword.lower() in main_text_html.lower() for keyword in self.EXCLUDE_KEYWORDS):
                logger.info(f"Skipping article due to excluded keyword in main text: {title}")
                return

            article = {
                'title': title,
                'date_time': date_time,
                'category': category,
                'url': response.url,
                'photo_url': photo_url,
                'summary': summary,
                'tags': tags,
                'main_text': main_text_html,
                'source': domain
            }

            logger.info(f"Processing article from {domain}: {title}")

            if not self.collection.find_one({'url': article['url']}):
                self.collection.insert_one(article)
                logger.info(f"Article inserted: {title}")
            else:
                logger.info(f"Article already exists: {title}")
        except Exception as e:
            logger.error(f"Error parsing article from {domain}: {e}")

    def parse_date(self, date_str):
        for fmt in ('%d/%m/%Y, %H:%M', '%d.%m.%Y • %H:%M', '%d.%m.%Y', '%d/%m/%Y'):
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        logger.error(f"Date format not matched for: {date_str}")
        return None

def run_spiders():
    configure_logging()
    runner = CrawlerRunner({
        'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
        'LOG_LEVEL': 'DEBUG'
    })
    runner.crawl(NewsSpider)
    d = runner.join()
    d.addBoth(lambda _: reactor.stop())
    reactor.run()

def schedule_scraping():
    task.LoopingCall(run_spiders).start(3600)  # Run every hour

def run_flask():
    app.run(debug=True, use_reloader=False)

if __name__ == '__main__':
    # Start the Flask app in a separate thread
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.start()

    # Start the scraping scheduler after the Flask app is running
    schedule_scraping()
