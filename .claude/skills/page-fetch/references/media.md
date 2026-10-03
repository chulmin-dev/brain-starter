# 미디어 추출 — yt-dlp
<!-- last_verified: 2026-06-12 -->

> yt-dlp는 여러 플랫폼을 지원하는 범용 미디어 추출 도구. 지원 범위는 설치 버전과 현재 공개 접근 상태에 따라 달라진다.
> 영상, 오디오, 팟캐스트, 라이브 스트리밍 — 미디어 URL이면 yt-dlp를 먼저 시도한다.

## 회수 범위와 중단 조건

canonical `SKILL.md`의 실행 경계를 따른다. 공개·읽기 전용 회수만 허용하며 로그인,
CAPTCHA, 페이월은 우회하지 않는다. 설치·PO token 구성·browser cookie 수입·운영 설정
변경은 영상 요약/자막 요청의 자동 후속 작업이 아니다. URL/검색어는 안전한 argv/env로 전달한다.

요약·분석 요청을 "전체 자막 회수"로 대체하지 않는다. 메타데이터·자막 존재·설명·챕터 등
대체 근거를 먼저 확인한다. 안정적인 자막 회수가 두 번 실패하거나 짧은 유한 예산에
도달하면 반복 client/token 변경을 멈추고 `Evidence used`와 `Limitations`를 붙인
근거 범위 내 답변을 제공한다. 전체 자막 미회수는 영상 내용 부재의 증거가 아니다.

매 호출에 별도의 출력 디렉토리를 사용하고 이번 호출이 만든 정확한 파일만 읽는다.
이전 호출의 자막 파일이나 다른 언어/영상 파일을 섞지 않는다. 메타데이터 조회는
영상/오디오 다운로드로 확대하지 않는다. 아래 `--ignore-config`는 상속된 설정으로
쿠키·프록시·다운로드 동작이 켜지는 것을 피한다. 별도의 유한 tool timeout도 지정한다.

## 설치 확인

```bash
which yt-dlp || node .claude/skills/page-fetch/python-runtime.cjs -m yt_dlp --version
```

- `yt-dlp` 명령어가 PATH에 있으면 그대로 사용
- 없으면 `node .claude/skills/page-fetch/python-runtime.cjs -m yt_dlp`로 대체 (아래 모든 명령어에서 치환)
- 미설치 시 의존성 blocker로 보고한다. 조회 실패를 이유로 `pip install`을 실행하지 않는다.

## 핵심 명령어 (모든 지원 사이트 공통)

### 메타데이터 추출 (가장 범용)

```bash
yt-dlp --ignore-config --no-playlist --dump-json "URL"
```

title, uploader, duration, view_count, description, tags 등 구조화 JSON 반환.
metadata 성공은 자막·전체 영상 내용을 검증했다는 뜻이 아니다.

### 자막 추출

```bash
yt-dlp --ignore-config --no-playlist --write-sub --write-auto-sub --sub-lang "en,ko" --skip-download -o "%(id)s.%(ext)s" "URL"
```

터미널 `cwd`를 이번 호출의 새 출력 디렉토리로 지정한다. 생성된 정확한 자막 파일을
native `read`로 읽고 언어·자동생성 여부를 표시한다. 자막 제공 여부는 영상별로 확인한다.

### 검색

```bash
# YouTube
yt-dlp --ignore-config --dump-json "ytsearch5:{검색어}"

# SoundCloud
yt-dlp --ignore-config --dump-json "scsearch5:{검색어}"

# Dailymotion
yt-dlp --ignore-config --dump-json "dailymotionsearch5:{검색어}"

# Yahoo
yt-dlp --ignore-config --dump-json "yahoosearch5:{검색어}"
```

### 채널/플레이리스트 목록 (다운로드 없이)

```bash
yt-dlp --ignore-config --flat-playlist --playlist-end 20 --dump-json "채널_URL"
```

title, id, url, duration 반환. 위 예시는 최대 20개이며 채널 전체가 아니다.
사용자가 요청한 범위와 실제 수집 개수를 구분한다.

### 댓글 추출 (YouTube)

```bash
yt-dlp --ignore-config --no-playlist --write-comments --skip-download --write-info-json \
  --extractor-args "youtube:max_comments=20" \
  -o "%(id)s.%(ext)s" "URL"
```

## 지원 플랫폼 카테고리

### 영상

| 사이트 | 메타데이터 | 자막 | 검색 | 비고 |
|--------|----------|------|------|------|
| YouTube | O | O (자동생성 포함) | `ytsearch` | 최고 지원 |
| Vimeo | O | O (사이트 제공 시) | X | 학술/다큐 콘텐츠 풍부 |
| Twitch | O (VOD/클립) | X | X | 기술 스트리밍 |
| TikTok | O | X | X | 공개 계정만 |
| Dailymotion | O | O | `dailymotionsearch` | |
| Rumble | O | X | X | |
| PeerTube | O | X | X | 탈중앙화 |

### 오디오/팟캐스트

| 사이트 | 메타데이터 | 검색 | 비고 |
|--------|----------|------|------|
| SoundCloud | O | `scsearch` | 검색까지 가능 — 최고 |
| Apple Podcasts | O | X | RSS 기반 |
| TuneIn | O | X | |
| acast | O | X | 채널 단위 지원 |
| Spreaker | O | X | |
| Audius | O | X | 블록체인 기반 |

### 한국 플랫폼

| 사이트 | Extractor | 비고 |
|--------|-----------|------|
| Naver TV | `Naver`, `Naver:live` | |
| Kakao | `Kakao` | |
| SBS | `SBS`, `sbs.co.kr` | |
| JTBC | `JTBC`, `JTBC:program` | |
| Chzzk | `chzzk:video`, `chzzk:live` | 네이버 스트리밍 |
| Soop (구 AfreecaTV) | `soop`, `soop:live` | |
| Daum | `daum.net`, `daum.net:clip` | |
| Weverse | `Weverse`, `WeverseLive` | K-팝 팬덤 |

### 뉴스 VOD

| 사이트 | 비고 |
|--------|------|
| BBC | 공개 VOD |
| ABC (호주) | iview |
| CBS News | |
| NBC News | 차단 많음 |

> 뉴스 사이트는 직접 URL보다 **YouTube 공식 채널 경유**가 더 안정적.
> 예: `ytsearch:BBC News {키워드}`

## 고급 옵션 (2026 현행화)

### --impersonate — WAF/봇 차단 우회

`--impersonate`는 설치된 `yt-dlp[curl-cffi]` 엑스트라가 필요하다.
없으면 미시도 사유로 보고하고 자동 설치하거나 인증 장벽을 우회하지 않는다.

```bash
# Chrome 최신으로 위장
yt-dlp --ignore-config --no-playlist --impersonate "chrome" --dump-json "URL"

# 지원 타겟 목록 확인
yt-dlp --list-impersonate-targets
```

### player_client 로테이션 — YouTube 추출 실패 시

공개 영상의 지원 client 문제가 확인되고 남은 시도 예산이 있을 때만 대체 client를
검토한다. 빈 결과만으로 접근 제어를 우회하거나 모든 client를 순회하지 않는다:

```bash
# 지원되는 공개 client 대안 (현재 버전에서 사용 가능한지 확인)
yt-dlp --ignore-config --no-playlist --extractor-args "youtube:player_client=tv" --dump-json "URL"

# IOS 클라이언트
yt-dlp --ignore-config --no-playlist --extractor-args "youtube:player_client=ios" --dump-json "URL"

# 대안을 연속 실행하는 체크리스트가 아니다. 위의 회수 예산과 중단 조건이 우선한다.
```

### -N (병렬 다운로드)

사용자가 실제 미디어 다운로드를 요청한 경우에만 `-N`으로 병렬화:

```bash
yt-dlp --ignore-config --no-playlist -N 4 -o "%(id)s.%(ext)s" "URL"
```

> 별도 downloader를 자동 설치하지 않는다. 유지보수 중단·CVE 같은 보안 주장은
> 현재 확인한 근거 없이 단정하지 않는다.

### 자막 후처리 (중복 제거)

자동 생성 자막(`--write-auto-sub`)은 행간 타임스탬프 중복이 발생한다:

```bash
# .vtt → 중복 제거 후 순수 텍스트
node .claude/skills/page-fetch/python-runtime.cjs -c "
import re, sys
text = open(sys.argv[1], encoding='utf-8').read()
# 헤더/타임스탬프/빈 줄 제거
lines = [l for l in text.splitlines()
         if l and not re.match(r'WEBVTT|^\d+$|-->', l)
         and not re.match(r'\d{2}:\d{2}', l)]
# 연속 중복 제거
deduped = [lines[i] for i in range(len(lines))
           if i == 0 or lines[i] != lines[i-1]]
print('\n'.join(deduped))
" "<absolute-local-subtitle-path>"
```

## 익명 추출 제한

플랫폼이 로그인, CAPTCHA 또는 별도 토큰을 요구하면 제한으로 보고한다.
이 템플릿에는 토큰 생성 plugin/provider가 포함되어 있지 않다. 조회 실패를
이유로 별도 provider를 설치하거나 쿠키·토큰을 생성·전달하지 않는다.

→ 미디어 에스컬레이션 경로 전체: [fallback.md](fallback.md)

## 주의사항

- 자동 생성 자막의 행간 중복은 위의 자막 후처리 예시로 제거한다.
- generic extractor의 현재 성공률은 미측정 — 지원 extractor와 실제 결과를 구분
- 페이월/로그인/CAPTCHA는 우회하지 않고 blocker로 보고
- `--dump-json`이 가장 안전한 범용 명령 (다운로드 없음, 메타데이터만)
