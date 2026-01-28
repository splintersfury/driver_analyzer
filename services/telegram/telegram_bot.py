#!/usr/bin/env python3
"""
Telegram Bot for Driver Analyzer notifications.

Commands:
    /start - Welcome message
    /watch <sha256> - Watch a driver for completion notification
    /unwatch <sha256> - Stop watching a driver
    /list - Show watched drivers
    /status - Show pending tasks per Karton service
    /summary - Show MWDB upload and analysis statistics
    /chatid - Show your chat ID (for configuration)
"""

import os
import logging
import json
import asyncio
from datetime import datetime

import redis
import requests
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from mwdblib import MWDB

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
REDIS_HOST = os.environ.get("KARTON_REDIS_HOST", "karton-redis")
MWDB_API_URL = os.environ.get("MWDB_API_URL", "http://mwdb-core:8080/api/")
MWDB_API_KEY = os.environ.get("MWDB_API_KEY")

# Redis key prefixes
WATCH_KEY = "telegram:watch"  # Set of watched sha256 hashes


class DriverAnalyzerBot:
    """Telegram bot for driver analyzer notifications."""

    def __init__(self):
        self.redis = redis.Redis(host=REDIS_HOST, port=6379, decode_responses=True)
        # Ensure key is clean and strip whitespace
        api_key = MWDB_API_KEY.strip() if MWDB_API_KEY else None
        self.mwdb = MWDB(api_url=MWDB_API_URL, api_key=api_key)

    # --- Command Handlers ---

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Send welcome message."""
        await update.message.reply_text(
            "🚗 *Driver Analyzer Bot*\n\n"
            "I'll notify you when drivers you're watching complete analysis.\n\n"
            "*Commands:*\n"
            "• `/watch <sha256>` - Watch a driver\n"
            "• `/unwatch <sha256>` - Stop watching\n"
            "• `/list` - Show watched drivers\n"
            "• `/status` - Karton queue status\n"
            "• `/summary` - MWDB statistics\n"
            "• `/chatid` - Show your chat ID",
            parse_mode="Markdown"
        )

    async def chatid(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show user's chat ID."""
        chat_id = update.effective_chat.id
        await update.message.reply_text(
            f"🆔 Your Chat ID: `{chat_id}`\n\n"
            "Use this in your `.env` file:\n"
            f"`TELEGRAM_CHAT_ID={chat_id}`",
            parse_mode="Markdown"
        )

    async def watch(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Add driver to watch list."""
        if not context.args:
            await update.message.reply_text(
                "❌ Usage: `/watch <sha256>`\n"
                "Example: `/watch a1b2c3d4e5...`",
                parse_mode="Markdown"
            )
            return

        sha256 = context.args[0].lower().strip()
        chat_id = str(update.effective_chat.id)

        # Validate SHA256 format (basic check)
        if len(sha256) < 8:
            await update.message.reply_text("❌ Invalid hash. Please provide a valid SHA256.")
            return

        # Store: hash -> set of chat_ids
        self.redis.sadd(f"{WATCH_KEY}:{sha256}", chat_id)
        # Also store reverse mapping: chat_id -> set of hashes
        self.redis.sadd(f"{WATCH_KEY}:user:{chat_id}", sha256)

        await update.message.reply_text(
            f"✅ Now watching: `{sha256[:16]}...`\n\n"
            "You'll be notified when analysis completes.",
            parse_mode="Markdown"
        )

    async def unwatch(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Remove driver from watch list."""
        if not context.args:
            await update.message.reply_text(
                "❌ Usage: `/unwatch <sha256>`",
                parse_mode="Markdown"
            )
            return

        sha256 = context.args[0].lower().strip()
        chat_id = str(update.effective_chat.id)

        self.redis.srem(f"{WATCH_KEY}:{sha256}", chat_id)
        self.redis.srem(f"{WATCH_KEY}:user:{chat_id}", sha256)

        await update.message.reply_text(
            f"🔕 Stopped watching: `{sha256[:16]}...`",
            parse_mode="Markdown"
        )

    async def list_watched(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """List all watched drivers for this user."""
        chat_id = str(update.effective_chat.id)
        watched = self.redis.smembers(f"{WATCH_KEY}:user:{chat_id}")

        if not watched:
            await update.message.reply_text("📭 You're not watching any drivers.")
            return

        msg = "👀 *Watched Drivers:*\n\n"
        for sha256 in sorted(watched):
            # Try to get driver name from MWDB
            name = self._get_driver_name(sha256)
            if name:
                msg += f"• `{sha256[:12]}...` ({name})\n"
            else:
                msg += f"• `{sha256[:12]}...`\n"

        await update.message.reply_text(msg, parse_mode="Markdown")

    async def status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show Karton queue status."""
        try:
            # Get all Karton queues from Redis
            queues = self._get_karton_queue_status()

            if not queues:
                await update.message.reply_text("📊 No pending tasks in queues.")
                return

            msg = "📊 *Karton Queue Status:*\n\n"
            total = 0
            for service, count in sorted(queues.items()):
                emoji = "🔴" if count > 100 else "🟡" if count > 10 else "🟢"
                msg += f"{emoji} {service}: {count}\n"
                total += count

            msg += f"\n*Total pending:* {total}"
            await update.message.reply_text(msg, parse_mode="Markdown")

        except Exception as e:
            logger.error(f"Error getting queue status: {e}")
            await update.message.reply_text(f"❌ Error: {e}")

    async def summary(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show MWDB statistics."""
        try:
            stats = self._get_mwdb_stats()

            msg = "📈 *MWDB Statistics:*\n\n"
            msg += f"📁 Total uploads: {stats.get('total', 'N/A')}\n"
            msg += f"🔍 Analyzed: {stats.get('analyzed', 'N/A')}\n"
            msg += f"⚠️ Vulnerable: {stats.get('vulnerable', 'N/A')}\n"
            msg += f"✅ Clean: {stats.get('clean', 'N/A')}\n"
            msg += f"⏳ Queued: {stats.get('queued', 'N/A')}\n"
            msg += f"❓ Failed/Other: {stats.get('other', 'N/A')}\n"

            await update.message.reply_text(msg, parse_mode="Markdown")

        except Exception as e:
            logger.error(f"Error getting MWDB stats: {e}")
            await update.message.reply_text(f"❌ Error: {e}")

    # --- Helper Methods ---

    def _get_driver_name(self, sha256: str) -> str:
        """Get driver name from MWDB."""
        try:
            obj = self.mwdb.query_file(sha256)
            if obj:
                return obj.file_name
        except:
            pass
        return ""

    def _get_karton_queue_status(self) -> dict:
        """Get pending task count per Karton service from Redis."""
        queues = {}
        try:
            # Karton keys: karton.queue.priority:identity
            # Use 'karton.queue*' to match keys with dots (e.g. karton.queue.normal:...)
            for key in self.redis.scan_iter(match="karton.queue*"):
                queue_len = self.redis.llen(key)
                if queue_len > 0:
                    # Clean up key name for display
                    service_name = key.replace("karton.queue.", "").replace("karton.queue:", "")
                    queues[service_name] = queue_len
        except Exception as e:
            logger.error(f"Error scanning Redis: {e}")
        return queues

    def _get_mwdb_stats(self) -> dict:
        """Get statistics from MWDB and Redis."""
        stats = {
            "total": 0,
            "analyzed": 0,
            "vulnerable": 0,
            "clean": 0,
            "queued": 0,
            "other": 0  # Failed or manual uploads not in pipeline
        }

        try:
            # mwdblib count_files is optimized
            stats["total"] = self.mwdb.count_files(query='md5:*')
            stats["vulnerable"] = self.mwdb.count_files(query='tag:vulnerable')
            stats["analyzed"] = self.mwdb.count_files(query='attribute.ioctl_verdict:*')
            
            # Get actual queued count from Redis
            queues = self._get_karton_queue_status()
            stats["queued"] = sum(queues.values())

            stats["clean"] = max(0, stats["analyzed"] - stats["vulnerable"])
            
            # "Other" are files that are neither analyzed nor currently queued
            # (e.g. failed analysis, crashed, or manual uploads not in pipeline)
            stats["other"] = max(0, stats["total"] - stats["analyzed"] - stats["queued"])

        except Exception as e:
            logger.error(f"Error fetching MWDB stats: {e}")

        return stats

    def run(self):
        """Start the bot."""
        if not TELEGRAM_BOT_TOKEN:
            logger.error("TELEGRAM_BOT_TOKEN not set!")
            return

        logger.info("Starting Driver Analyzer Telegram Bot...")

        # Create application
        app = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

        # Add handlers
        app.add_handler(CommandHandler("start", self.start))
        app.add_handler(CommandHandler("chatid", self.chatid))
        app.add_handler(CommandHandler("watch", self.watch))
        app.add_handler(CommandHandler("unwatch", self.unwatch))
        app.add_handler(CommandHandler("list", self.list_watched))
        app.add_handler(CommandHandler("status", self.status))
        app.add_handler(CommandHandler("summary", self.summary))

        # Run polling
        logger.info("Bot is running...")
        app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    bot = DriverAnalyzerBot()
    bot.run()
