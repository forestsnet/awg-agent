"""forestsnet awg-agent."""
import os

__version__ = "1.0.1"

# Короткий хэш коммита, из которого собран образ. Проставляет CI через
# --build-arg BUILD_SHA; локальная сборка честно говорит «dev».
#
# Нужен не для красоты: «обновил агент» и «агент обновился» — разные
# события, и без хэша в панели их не различить. Особенно когда образ
# плавающий (latest), а контейнер пересоздавали в прошлом месяце.
__build__ = (os.environ.get("AGENT_BUILD") or "dev").strip()[:7] or "dev"

REPO_URL = "https://github.com/forestsnet/awg-agent"
