# JSON API 직접 호출
<!-- last_verified: 2026-06-24 -->

> URL 변형이나 공개 엔드포인트로 구조화된 JSON을 직접 가져오는 패턴.
> 인증 불필요. Jina Reader보다 빠르고 정확한 구조화 데이터 획득.

## Reddit

> **Phase-0 우선**: `page-fetch`는 `.rss`를 먼저 시도한다 ([rss.md](rss.md) 참조).
> `.json` API는 현재 대부분 **403 WAF-gated** (2026-06-24 curl 직접 측정: 403).
> `.rss`도 IP-reputation WAF 적용 — 클라우드/VPS 출구 IP에서 403 가능 (동일 측정: 403).
> Phase-0 `.rss` 성공 시 `.json`은 시도하지 않는다. 두 경로 모두 실패 시 grid 폴백.

**Mobile User-Agent 필수** (없으면 403/429 — 현재 UA 있어도 403 빈번).

```bash
UA="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15"

# 서브레딧 핫 포스트
curl -sL -H "User-Agent: $UA" "https://www.reddit.com/r/{subreddit}/hot.json?limit=10"

# 검색
curl -sL -H "User-Agent: $UA" "https://www.reddit.com/r/{subreddit}/search.json?q={query}&restrict_sr=1"

# 포스트 + 댓글
curl -sL -H "User-Agent: $UA" "https://www.reddit.com/r/{subreddit}/comments/{post_id}/{slug}/.json"

# 정렬: hot.json / new.json / top.json?t=week
```

데이터: `title`, `author`, `score`, `selftext`(전문), `num_comments`, `created_utc`
댓글: 응답 `[1]` 배열에 재귀적 트리

### Reddit 폴백 — redlib / farside

reddit.com이 직접 차단되거나 429가 반복될 때 redlib 프런트엔드 경유:

```bash
# redlib 공개 인스턴스 (farside.link가 살아있는 인스턴스로 자동 라우팅)
curl -sL "https://farside.link/redlib/r/{subreddit}.json?limit=10"

# 직접 인스턴스 예시 (farside 불가 시)
curl -sL "https://redlib.tux.pizza/r/{subreddit}/hot.json?limit=10"
```

> redlib/farside는 best-effort — 인스턴스별 가용성이 다르다. reddit.com 직접 호출이 성공하면 우선 사용한다.

## Hacker News (Firebase API)

Rate limit 사실상 없음.

```bash
# 탑 스토리 ID 목록
curl -sL "https://hacker-news.firebaseio.com/v0/topstories.json?limitToFirst=10&orderBy=%22%24key%22"

# 개별 아이템
curl -sL "https://hacker-news.firebaseio.com/v0/item/{id}.json"

# 변형: beststories / newstories / askstories / showstories
```

데이터: `title`, `url`, `score`, `by`(작성자), `descendants`(댓글수), `kids`(댓글 ID)

배치 조회:
```bash
node .claude/skills/page-fetch/python-runtime.cjs -c "
import urllib.request, json
ids = json.load(urllib.request.urlopen('https://hacker-news.firebaseio.com/v0/topstories.json?limitToFirst=5&orderBy=\"\$key\"'))
for id in ids:
    item = json.load(urllib.request.urlopen(f'https://hacker-news.firebaseio.com/v0/item/{id}.json'))
    print(f'[{item.get(\"score\",0)}] {item.get(\"title\")}')
    print(f'  {item.get(\"url\",\"N/A\")[:60]}')
"
```

## Lobste.rs

Rate limit 없음. HN보다 작지만 고품질 큐레이션.

```bash
# 핫 스토리
curl -sL "https://lobste.rs/hottest.json"

# 태그별 (ai, programming, web, security 등)
curl -sL "https://lobste.rs/t/ai.json"

# 최신
curl -sL "https://lobste.rs/newest.json"

# 개별 스토리 + 댓글
curl -sL "https://lobste.rs/s/{short_id}.json"
```

데이터: `title`, `url`, `score`, `comment_count`, `tags`, `submitter_user`

## dev.to

```bash
# 태그별 최신
curl -sL "https://dev.to/api/articles?tag=ai&per_page=5"

# 이번 주 탑
curl -sL "https://dev.to/api/articles?top=7&per_page=5"

# 특정 유저
curl -sL "https://dev.to/api/articles?username={user}&per_page=5"
```

데이터: `title`, `user.name`, `public_reactions_count`, `reading_time_minutes`, `tags`

## npm Registry

```bash
# 패키지 최신 버전
curl -sL "https://registry.npmjs.org/{package}/latest"

# 패키지 검색
curl -sL "https://registry.npmjs.org/-/v1/search?text={query}&size=5"

# 다운로드 통계
curl -sL "https://api.npmjs.org/downloads/range/last-month/{package}"
```

## PyPI

```bash
# 패키지 정보
curl -sL "https://pypi.org/pypi/{package}/json"

# 다운로드 통계
curl -sL "https://pypistats.org/api/packages/{package}/recent"
```

## Wikipedia

```bash
# 페이지 요약
curl -sL "https://en.wikipedia.org/api/rest_v1/page/summary/{title}"
# 한국어: https://ko.wikipedia.org/api/rest_v1/page/summary/{title}

# 검색
curl -sL "https://en.wikipedia.org/w/api.php?action=opensearch&search={query}&limit=5&format=json"
```

## V2EX

```bash
curl -sL "https://www.v2ex.com/api/topics/hot.json" -H "User-Agent: insane-search/1.0"
```

## RSS 피드

→ [rss.md](rss.md)로 이동. 한국 언론 RSS, Google News RSS, feedparser 사용법 등 상세 가이드 참조.
