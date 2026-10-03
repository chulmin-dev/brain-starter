# X/Twitter 접근 전략
<!-- last_verified: 2026-06-24 -->

> WebFetch는 402로 차단됨. 아래 방법으로 우회한다. 모두 API 키/인증 불필요.
> **Phase-0**: `page-fetch`는 X URL을 자동 감지해 아래 공식 엔드포인트를
> 우선 시도한다. `--no-phase0` 플래그로 건너뛸 수 있다.

## 검색 (트윗 발견)

```python
WebSearch(query="site:x.com {검색어}")
```

WebSearch는 X 포스트를 검색 결과로 반환한다. 제목, snippet, URL을 획득할 수 있지만 트윗 전문이나 engagement 수치는 없다.

## 타임라인 조회 — Syndication API

특정 핸들의 최근 ~100개 트윗 + engagement 수치(likes, RTs) 제공.

### 엔드포인트

```
https://syndication.twitter.com/srv/timeline-profile/screen-name/{handle}
```

### 원샷 스크립트

```bash
curl -sL "https://syndication.twitter.com/srv/timeline-profile/screen-name/{handle}" | \
node .claude/skills/page-fetch/python-runtime.cjs -c "
import sys, json, re, html
content = sys.stdin.read()
match = re.search(r'__NEXT_DATA__.*?>(.*?)</script>', content)
if match:
    data = json.loads(match.group(1))
    for e in data['props']['pageProps']['timeline']['entries']:
        if e['type'] == 'tweet':
            t = e['content']['tweet']
            print(f\"@{t['user']['screen_name']} ({t.get('created_at','?')})\")
            print(f\"  {html.unescape(t.get('full_text',''))[:300]}\")
            print(f\"  Likes: {t.get('favorite_count',0)} | RTs: {t.get('retweet_count',0)}\")
            print('---')
"
```

### 가져올 수 있는 데이터

| 필드 | 경로 | 예시 |
|------|------|------|
| 트윗 전문 | `tweet.full_text` | "Give your agent the..." |
| 작성자 핸들 | `tweet.user.screen_name` | "openclaw" |
| 작성자 이름 | `tweet.user.name` | "OpenClaw" |
| 좋아요 수 | `tweet.favorite_count` | 1929 |
| RT 수 | `tweet.retweet_count` | 169 |
| 작성 시각 | `tweet.created_at` | "Mon Apr 06 04:04:08 +0000 2026" |
| 트윗 ID | `tweet.id_str` | "<tweet-id>" |
| 미디어 URL | `tweet.entities.media[].media_url_https` | 이미지/동영상 URL |

### 제한

- 최근 ~100개 반환 (페이지네이션 불가)
- 비공개 계정 접근 불가
- 검색 기능 없음 (타임라인만)
- **저팔로워/신규 계정**: `hasResults: false` 반환 가능. 이 경우 oEmbed 개별 트윗 접근은 정상 동작하므로 "조합 패턴"으로 폴백.
- 비공식 엔드포인트 — X가 변경/차단 가능

## 개별 트윗 조회 — CDN Syndication (1순위)

Phase-0 주경로. 트윗 ID만 알면 구조화 JSON을 반환한다. 인증 불필요.
(2026-06-24 curl 직접 측정: id=20 → **HTTP 200**, `text` 필드 확인.)

### 엔드포인트

```
https://cdn.syndication.twimg.com/tweet-result?id={tweet_id}&token=a
```

### 사용법

```bash
curl -sL "https://cdn.syndication.twimg.com/tweet-result?id={tweet_id}&token=a"
```

### 응답 (JSON)

| 필드 | 설명 |
|------|------|
| `text` | 트윗 전문 |
| `id_str` | 트윗 ID |
| `created_at` | 작성 시각 |
| `favorite_count` | 좋아요 수 |
| `__typename` | `"Tweet"` (성공 지표) |

> `text` 필드 존재 여부로 성공 판정. 트윗 삭제/비공개 시 빈 응답 반환.

## 개별 트윗 조회 — oEmbed API (2순위 폴백)

CDN Syndication 실패 시 폴백. HTML blockquote 형태로 반환.
(2026-06-24 curl 직접 측정: id=20 → **HTTP 200**, `html` 필드 확인.)

### 엔드포인트

```
https://publish.twitter.com/oembed?url=https://x.com/{user}/status/{tweet_id}
```

### 사용법

```bash
curl -sL "https://publish.twitter.com/oembed?url=https://x.com/{user}/status/{tweet_id}"
```

### 응답 (JSON)

| 필드 | 설명 |
|------|------|
| `author_name` | 작성자 표시 이름 |
| `author_url` | 작성자 프로필 URL |
| `html` | 트윗 전문이 포함된 HTML blockquote |
| `url` | 트윗 원본 URL |

## 조합 패턴 (검색 → 상세)

```
1단계: WebSearch(query="site:x.com {키워드}") → 트윗 URL 획득
2단계: curl oEmbed API → 트윗 전문 획득
```

## 부가 폴백 (best-effort, 위 주경로 실패 시에만)

syndication + oEmbed가 주경로다. 아래는 그것이 실패했을 때만 시도한다.

### Nitter / Twiiit

Nitter(zedeus/nitter)는 2024년 초 공식 종료 선언 이후 공개 인스턴스 대부분이 비정상이다.
살아있는 인스턴스가 있으면 트윗 HTML을 반환하지만 가용성을 보장할 수 없다.

```bash
# Twiiit — 살아있는 Nitter 인스턴스로 자동 라우팅 시도
curl -sL "https://twiiit.com/{user}/status/{tweet_id}"

# 직접 Nitter 인스턴스 (가용 여부 사전 확인 필요)
curl -sL "https://nitter.net/{user}/status/{tweet_id}"
```

> 이 경로는 인스턴스 의존적이므로 결과를 신뢰하기 전 응답 내용을 검증한다.
> syndication/oEmbed가 성공하면 Nitter/Twiiit는 사용하지 않는다.

## 실패하는 방법 (사용하지 말 것)

| 방법 | 결과 | 원인 |
|------|------|------|
| WebFetch | 402 Payment Required | Claude Code의 WebFetch 제한 |
| Wayback Machine | OG 메타태그만 | SPA 렌더링 안 됨 |
| Mobile UA curl | OG 메타태그만 | SPA 렌더링 안 됨 |
| RSS | 엔드포인트 없음 | X는 RSS 지원 중단 |
