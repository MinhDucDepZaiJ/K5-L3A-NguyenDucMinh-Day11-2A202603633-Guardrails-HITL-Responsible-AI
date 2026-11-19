import asyncio
from types import SimpleNamespace

from assignment.rate_limiter import RateLimitPlugin


def test_rate_limit_per_user():
    async def run():
        plugin = RateLimitPlugin(
            max_requests=3,
            window_seconds=60,
        )

        user_a = SimpleNamespace(user_id="user_a")
        user_b = SimpleNamespace(user_id="user_b")

        for _ in range(3):
            result = await plugin.on_user_message_callback(
                invocation_context=user_a,
                user_message=None,
            )
            assert result is None

        blocked = await plugin.on_user_message_callback(
            invocation_context=user_a,
            user_message=None,
        )
        assert blocked is not None

        allowed = await plugin.on_user_message_callback(
            invocation_context=user_b,
            user_message=None,
        )
        assert allowed is None

        assert plugin.total_count == 5
        assert plugin.blocked_count == 1

    asyncio.run(run())
