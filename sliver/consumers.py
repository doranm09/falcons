from channels.generic.websocket import AsyncJsonWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import User
from .models import SliverSession, SliverJob, SliverEvent, Engagement
import asyncio
import json


class SliverDashboardConsumer(AsyncJsonWebsocketConsumer):
    """WebSocket consumer for real-time Sliver dashboard updates."""

    async def connect(self):
        """Handle WebSocket connection."""
        if self.scope["user"].is_anonymous:
            await self.close()
            return

        self.user = self.scope["user"]
        self.user_id = self.user.id

        # Subscribe to user's personal dashboard updates
        await self.channel_layer.group_add(
            f"sliver_user_{self.user_id}",
            self.channel_name
        )

        # Subscribe to general Sliver updates (for all users)
        await self.channel_layer.group_add(
            "sliver_broadcast",
            self.channel_name
        )

        await self.accept()
        await self.send_json({
            "type": "connection_established",
            "message": "Connected to Sliver real-time updates",
            "user_id": self.user_id
        })

    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        # Leave user-specific group
        await self.channel_layer.group_discard(
            f"sliver_user_{self.user_id}",
            self.channel_name
        )

        # Leave broadcast group
        await self.channel_layer.group_discard(
            "sliver_broadcast",
            self.channel_name
        )

    async def receive_json(self, content):
        """Handle messages from WebSocket client."""
        message_type = content.get('type')

        if message_type == 'subscribe_engagement':
            engagement_id = content.get('engagement_id')
            if engagement_id:
                await self.subscribe_to_engagement(engagement_id)

        elif message_type == 'unsubscribe_engagement':
            engagement_id = content.get('engagement_id')
            if engagement_id:
                await self.unsubscribe_from_engagement(engagement_id)

        elif message_type == 'ping':
            await self.send_json({
                "type": "pong",
                "timestamp": await self.get_timestamp()
            })

    async def subscribe_to_engagement(self, engagement_id):
        """Subscribe to real-time updates for a specific engagement."""
        # Verify user has access to this engagement
        has_access = await self.check_engagement_access(engagement_id)
        if has_access:
            await self.channel_layer.group_add(
                f"engagement_{engagement_id}",
                self.channel_name
            )
            await self.send_json({
                "type": "subscription_success",
                "engagement_id": engagement_id
            })
        else:
            await self.send_json({
                "type": "subscription_denied",
                "engagement_id": engagement_id
            })

    async def unsubscribe_from_engagement(self, engagement_id):
        """Unsubscribe from engagement updates."""
        await self.channel_layer.group_discard(
            f"engagement_{engagement_id}",
            self.channel_name
        )
        await self.send_json({
            "type": "unsubscribed",
            "engagement_id": engagement_id
        })

    # Event handlers for different types of updates

    async def session_update(self, event):
        """Send session update to client."""
        await self.send_json({
            "type": "session_update",
            "data": event["data"]
        })

    async def job_update(self, event):
        """Send job status update to client."""
        await self.send_json({
            "type": "job_update",
            "data": event["data"]
        })

    async def event_notification(self, event):
        """Send event notification to client."""
        await self.send_json({
            "type": "event_notification",
            "data": event["data"]
        })

    async def loot_collected(self, event):
        """Send loot collection notification."""
        await self.send_json({
            "type": "loot_collected",
            "data": event["data"]
        })

    # Database-sync helper methods

    @database_sync_to_async
    def check_engagement_access(self, engagement_id):
        """Check if user has access to the engagement."""
        try:
            engagement = Engagement.objects.get(id=engagement_id)
            return engagement.operator == self.user
        except Engagement.DoesNotExist:
            return False

    @database_sync_to_async
    def get_timestamp(self):
        """Get current timestamp."""
        from django.utils import timezone
        return timezone.now().isoformat()


class SliverSessionMonitorConsumer(AsyncJsonWebsocketConsumer):
    """Consumer for real-time session monitoring."""

    async def connect(self):
        """Handle connection for session monitoring."""
        if self.scope["user"].is_anonymous:
            await self.close()
            return

        self.user = self.scope["user"]

        # Extract engagement_id from URL parameters
        self.engagement_id = self.scope['url_route']['kwargs'].get('engagement_id')
        if self.engagement_id:
            has_access = await self.check_engagement_access(self.engagement_id)
            if not has_access:
                await self.close()
                return

        await self.channel_layer.group_add(
            f"sessions_user_{self.user.id}",
            self.channel_name
        )

        await self.accept()

        # Send initial session data
        await self.send_initial_sessions()

    async def disconnect(self, close_code):
        """Handle disconnection."""
        await self.channel_layer.group_discard(
            f"sessions_user_{self.user.id}",
            self.channel_name
        )

    async def send_initial_sessions(self):
        """Send initial session data when client connects."""
        sessions_data = await self.get_sessions_data()
        await self.send_json({
            "type": "initial_sessions",
            "sessions": sessions_data
        })

    async def session_status_change(self, event):
        """Handle session status changes."""
        await self.send_json({
            "type": "session_status_change",
            "session_id": event["session_id"],
            "status": event["status"],
            "last_checkin": event["last_checkin"]
        })

    async def new_session_detected(self, event):
        """Handle new session detection."""
        await self.send_json({
            "type": "new_session",
            "session": event["session_data"]
        })

    async def session_lost(self, event):
        """Handle session loss."""
        await self.send_json({
            "type": "session_lost",
            "session_id": event["session_id"]
        })

    @database_sync_to_async
    def get_sessions_data(self):
        """Get current sessions data."""
        queryset = SliverSession.objects.filter(
            engagement__operator=self.user
        ).select_related('engagement')

        if self.engagement_id:
            queryset = queryset.filter(engagement_id=self.engagement_id)

        sessions = []
        for session in queryset:
            sessions.append({
                'session_id': session.session_id,
                'name': session.name,
                'engagement': session.engagement.name,
                'status': session.status,
                'session_type': session.session_type,
                'hostname': session.hostname,
                'username': session.username,
                'os': session.os,
                'arch': session.arch,
                'is_online': session.is_online(),
                'last_checkin': session.last_checkin.isoformat() if session.last_checkin else None,
                'remote_address': session.remote_address,
                'transport': session.transport,
            })

        return sessions

    @database_sync_to_async
    def check_engagement_access(self, engagement_id):
        """Check engagement access."""
        try:
            engagement = Engagement.objects.get(id=engagement_id)
            return engagement.operator == self.user
        except Engagement.DoesNotExist:
            return False


class SliverJobMonitorConsumer(AsyncJsonWebsocketConsumer):
    """Consumer for real-time job monitoring."""

    async def connect(self):
        """Handle connection for job monitoring."""
        if self.scope["user"].is_anonymous:
            await self.close()
            return

        self.user = self.scope["user"]

        await self.channel_layer.group_add(
            f"jobs_user_{self.user.id}",
            self.channel_name
        )

        await self.accept()
        await self.send_json({"type": "job_monitor_connected"})

    async def disconnect(self, close_code):
        """Handle disconnection."""
        await self.channel_layer.group_discard(
            f"jobs_user_{self.user.id}",
            self.channel_name
        )

    async def job_status_update(self, event):
        """Handle job status updates."""
        await self.send_json({
            "type": "job_status_update",
            "job": event["job_data"]
        })

    async def job_completed(self, event):
        """Handle job completion."""
        await self.send_json({
            "type": "job_completed",
            "job": event["job_data"],
            "execution_time": event["execution_time"]
        })

    async def job_failed(self, event):
        """Handle job failure."""
        await self.send_json({
            "type": "job_failed",
            "job": event["job_data"],
            "error": event["error"]
        })


# Utility functions for broadcasting updates

async def broadcast_session_update(session_data):
    """Broadcast session update to all connected users."""
    from channels.layers import get_channel_layer
    channel_layer = get_channel_layer()

    await channel_layer.group_send(
        "sliver_broadcast",
        {
            "type": "session_update",
            "data": session_data
        }
    )

    # Send to specific user if applicable
    if 'user_id' in session_data:
        await channel_layer.group_send(
            f"sliver_user_{session_data['user_id']}",
            {
                "type": "session_update",
                "data": session_data
            }
        )


async def broadcast_job_update(job_data):
    """Broadcast job update to all connected users."""
    from channels.layers import get_channel_layer
    channel_layer = get_channel_layer()

    await channel_layer.group_send(
        "sliver_broadcast",
        {
            "type": "job_update",
            "data": job_data
        }
    )

    # Send to specific user
    if 'user_id' in job_data:
        await channel_layer.group_send(
            f"sliver_user_{job_data['user_id']}",
            {
                "type": "job_update",
                "data": job_data
            }
        )


async def broadcast_event_notification(event_data):
    """Broadcast event notification."""
    from channels.layers import get_channel_layer
    channel_layer = get_channel_layer()

    await channel_layer.group_send(
        "sliver_broadcast",
        {
            "type": "event_notification",
            "data": event_data
        }
    )

    # Send to engagement subscribers
    if 'engagement_id' in event_data:
        await channel_layer.group_send(
            f"engagement_{event_data['engagement_id']}",
            {
                "type": "event_notification",
                "data": event_data
            }
        )
