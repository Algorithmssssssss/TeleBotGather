import csv
import os
import logging
import feedparser
from bs4 import BeautifulSoup
from telegram import Update, InputFile
from telegram.ext import Application, CommandHandler, ContextTypes
from datetime import datetime
import re
from dateutil.relativedelta import relativedelta
import pretty_errors
import time

# Set up logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO)
# Set higher logging level for httpx to avoid all GET and POST requests being logged
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

# RSS feed URLs
rss_feed_urls = [
    "https://socprime.com/blog/feed/",
    "https://cybersecuritynews.com/category/vulnerability/feed/",
    "https://cybersecuritynews.com/category/zero-day/feed/",
    "https://cybersecuritynews.com/category/cyber-attack/feed/",
    "https://research.checkpoint.com/feed/"
]

# Channel ID of the destination channel
destination_channel_id = "@threatintel123"

# Fetch bot token from environment variable
bot_token = "7190494596:AAHrEvqsAd1e67pxNGqLVNqRDRYYGySGo0Y"

import csv
import os
import logging
import feedparser
from bs4 import BeautifulSoup
from telegram import Update, InputFile
from telegram.ext import Application, CommandHandler, ContextTypes
from datetime import datetime
import re
from dateutil.relativedelta import relativedelta
import pretty_errors
import time

# Set up logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO)
# Set higher logging level for httpx to avoid all GET and POST requests being logged
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

# RSS feed URLs
rss_feed_urls = [
    "https://socprime.com/blog/feed/",
    "https://cybersecuritynews.com/category/vulnerability/feed/",
    "https://cybersecuritynews.com/category/zero-day/feed/",
    "https://cybersecuritynews.com/category/cyber-attack/feed/",
    "https://research.checkpoint.com/feed/"
]

# Channel ID of the destination channel
destination_channel_id = "@threatintelligenceCyberOps"

# Fetch bot token from environment variable
bot_token = "7190494596:AAHrEvqsAd1e67pxNGqLVNqRDRYYGySGo0Y"

# Set up a dictionary to store sent items
sent_items = {}


async def fetch_rss_feed_and_send(update: Update,
                                  context: ContextTypes.DEFAULT_TYPE) -> None:
    """Fetch the RSS feeds and send their new contents to the destination channel."""
    try:
        for rss_feed_url in rss_feed_urls:
            # Parse the RSS feed
            feed = feedparser.parse(rss_feed_url)

            # Extract and send the latest feed items to the destination channel
            for entry in reversed(feed.entries[:15]):  # Reverse the loop order
                # Check if the entry has already been sent
                if entry.id in sent_items.get(rss_feed_url, []):
                    continue

                # Store the ID of the new entry
                if rss_feed_url not in sent_items:
                    sent_items[rss_feed_url] = []
                sent_items[rss_feed_url].append(entry.id)

                # Check if publication date is available, otherwise set to "N/A"
                pub_date = entry.published if 'published' in entry else "N/A"

                # Extract the summary of the news item
                summary = "Summary not available"
                if 'description' in entry:
                    soup = BeautifulSoup(entry.description, 'html.parser')
                    first_paragraph = soup.find('p')
                    if first_paragraph:
                        summary = first_paragraph.text.strip()

                # Extract the type of the news item (you can define your own logic here)
                news_type = extract_news_type(entry.title)

                # Pausing to avoid spamming
                time.sleep(2)

                # Construct the message
                message = f"<b>[{news_type}]</b>\n<b>{entry.title}</b>\n\nSummary: {summary}\n\nPublished: {pub_date}\n{entry.link}"
                await context.bot.send_message(chat_id=destination_channel_id,
                                               text=message,
                                               parse_mode='HTML')
    except Exception as e:
        logger.error(f"Error fetching and sending RSS feed: {e}")
        await update.message.reply_text(
            "Error fetching and sending RSS feed. Please try again later.")


async def check_sentID(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(sent_items)


async def check_status(update: Update,
                       context: ContextTypes.DEFAULT_TYPE) -> None:
    """Check the status of the bot."""
    await update.message.reply_text("The bot is running.")
    

async def send_reportdate(update: Update,
                          context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a report to the user based on provided date."""
    # Get the date parameter from the command
    date_str = context.args[0] if context.args else None

    # Validate the date format
    if date_str is None or not re.match(r'\d{2}-\d{2}-\d{2}', date_str):
        await update.message.reply_text("Please provide a valid date in the format dd-mm-yy.")
        return

    # Convert the date string to datetime object
    try:
        report_date = datetime.strptime(date_str, "%d-%m-%y")
    except ValueError:
        await update.message.reply_text("Invalid date format. Please provide a valid date in the format dd-mm-yy.")
        return

    # Calculate the start date (1 month ago from the provided date)
    start_date = report_date - relativedelta(months=1)
    print("Start date: ", start_date)

    # Convert RSS feed to CSV
    await convert_to_csv(start_date)

    # Send the CSV file to the user
    with open('threat_intelligence.csv', 'rb') as csv_file:
        await update.message.reply_document(
            document=InputFile(csv_file, filename='threat_intelligence.csv'))


async def send_report(update: Update,
                      context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a report to the user."""
    # Send report in CSV form
    await update.message.reply_text("Sending report in CSV format...")

    # Convert RSS feed to CSV
    await convert_to_csv()

    # Send the CSV file to the user
    with open('threat_intelligence.csv', 'rb') as csv_file:
        await update.message.reply_document(
            document=InputFile(csv_file, filename='threat_intelligence.csv'))


async def send_report_group(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a report to the channel."""
    # Convert RSS feed to CSV
    await convert_to_csv()

    # Send the CSV file to the channel
    with open('threat_intelligence.csv', 'rb') as csv_file:
        await context.bot.send_document(
            chat_id=destination_channel_id,
            document=InputFile(csv_file, filename='threat_intelligence.csv'),
            caption="CSV Report"
        )

    await update.message.reply_text("CSV report sent to the channel.")


async def convert_to_csv():
    """Convert RSS feed data to CSV format."""
    csv_data = []
    for rss_feed_url in rss_feed_urls:
        feed = feedparser.parse(rss_feed_url)
        for entry in feed.entries:
            # Parse and format the publish date
            pub_date = "N/A"
            if 'published' in entry:
                try:
                    pub_date = datetime.strptime(
                    entry.published, "%a, %d %b %Y %H:%M:%S %z").strftime("%d %b %Y")
                except ValueError: # Handle date format exceptions
                    pub_date = entry.published

            summary = "Summary not available"
            if 'description' in entry:
                soup = BeautifulSoup(entry.description, 'html.parser')
                first_paragraph = soup.find('p')
                if first_paragraph:
                    summary = first_paragraph.text.strip()

            # Extract the type of the news item
            news_type = extract_news_type(entry.title)

            # Extract CVE IDs
            cve_ids = extract_cve_ids(entry.description)

            csv_data.append([news_type, pub_date, cve_ids, entry.title, summary, entry.link])

    with open('threat_intelligence.csv', 'w', newline='', encoding='utf-8') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(
            ['Type (Tag)', 'Published Date', 'CVE', 'Title', 'Summary', 'Link'])
        csv_writer.writerows(csv_data)

# Extract news type tag
def extract_news_type(title):
    if 'Ransomware' in title:
        news_type = 'Ransomware'
    elif 'Malware' in title:
        news_type = 'Malware'
    elif 'Phishing' in title:
        news_type = 'Phishing'
    elif 'Botnet' in title:
        news_type = 'Botnet'
    elif 'iOS' in title:
        news_type = 'iOS'
    elif 'Android' in title:
        news_type = 'Android'
    elif 'Windows' in title:
        news_type = 'Windows'
    elif 'macOS' in title:
        news_type = 'macOS'
    elif '0-day' in title:
        news_type = 'Zero Day'
    elif 'Vulnerability' in title and 'Tool' in title:
        news_type = 'Tool'
    elif 'Vulnerability' in title:
        news_type = 'Vulnerability'
    elif 'Exploit' in title:
        news_type = 'Exploit'
    elif 'Zero-Day' in title:
        news_type = 'Zero Day'
    else:
        news_type = 'General'
    return news_type


def extract_cve_ids(description):
    """Extract the CVE IDs from the description."""
    cve_ids = re.findall(r'\bCVE-\d{4}-\d{4,7}\b', description)
    return ", ".join(cve_ids)


async def help_command(update: Update,
                       context: ContextTypes.DEFAULT_TYPE) -> None:
    """Display help message."""
    help_text = (
        "Available commands:\n"
        "/sendrss - Fetch and send RSS feed to the destination channel\n"
        "/status - Check the status of the bot\n"
        "/report - Send CSV Report back to the user\n"
        "/reportgroup - Send CSV to the channel\n"
        "/sentID - Check sent items\n"
        '/sendLink - Sending the source links back to the user\n'
        "/help - Display this help message")
    await update.message.reply_text(help_text)


def main() -> None:
    """Start the bot."""
    if bot_token is None:
        raise RuntimeError("Bot token environment variable not set.")

    # Create the Application and pass it your bot's token.
    application = Application.builder().token(bot_token).build()

    # Register command handlers
    application.add_handler(CommandHandler("sendrss", fetch_rss_feed_and_send))
    application.add_handler(CommandHandler("status", check_status))
    application.add_handler(CommandHandler("report", send_report))
    application.add_handler(CommandHandler("reportgroup", send_report_group))
    application.add_handler(CommandHandler("reportdate", send_reportdate))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("sentID", check_sentID))

    # Run the bot until the user presses Ctrl-C
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
