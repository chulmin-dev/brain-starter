# 이미지/갤러리 추출 — gallery-dl
<!-- last_verified: 2026-06-12 -->

> gallery-dl은 YouTube 전용이 아닌 범용 **이미지·갤러리·타임라인 미디어** 추출 도구.
> 1,800개 이상 사이트 지원. yt-dlp가 영상을 담당하듯 gallery-dl은 이미지·갤러리를 담당한다.
> subprocess 모델이라 engine 코드 수정 없이 사용 가능.

## 설치 확인

```bash
node .claude/skills/page-fetch/python-runtime.cjs -m gallery_dl --version
```

- Run commands from the vault root. If the executable is absent from PATH, use
  `node .claude/skills/page-fetch/python-runtime.cjs -m gallery_dl` instead.
- If missing, report the dependency limitation. Only after an explicit install
  request, use the local venv from SKILL.md, then:

```bash
node .claude/skills/page-fetch/python-runtime.cjs -m pip install --index-url https://pypi.org/simple gallery-dl
```

## 핵심 호출 규약 (다운로드 없이 데이터만)

### 메타데이터 + URL 목록 (가장 범용)

```bash
gallery-dl -j "URL"
```

`-j` (`--dump-json`): 각 파일의 메타데이터를 JSON으로 출력. 다운로드 없음.
URL, filename, extension, title, description, date 등 구조화 데이터 반환.

### URL만 추출

```bash
gallery-dl -g "URL"
```

`-g` (`--get-urls`): 미디어 URL 목록만 출력. 파이프라인에 적합.

### 시뮬레이션 (다운로드 없이 처리 여부 확인)

```bash
gallery-dl -s "URL"
```

`-s` (`--simulate`): 실제 다운로드 없이 extractor 동작만 확인.

### 범위 제한 (타임라인/갤러리 일부만)

```bash
gallery-dl -j --range "1-20" "URL"
```

`--range "1-20"`: 1번째~20번째 항목만 처리. 대형 갤러리/타임라인에 필수.

## 지원 플랫폼 카테고리

### 이미지 갤러리

| 사이트 | Extractor | 비고 |
|--------|-----------|------|
| Pixiv | `Pixiv*` | **OAuth refresh token 필수** — 익명 불가 |
| DeviantArt | `DeviantArt*` | 공개 작품은 익명 가능 |
| ArtStation | `artstation` | 공개 포트폴리오 |
| danbooru | `Danbooru*` | 태그 기반 갤러리 |
| gelbooru | `Gelbooru*` | |
| Flickr | `Flickr*` | 공개 앨범 익명 가능 |
| Imgur | `Imgur*` | 공개 갤러리 |

### 소셜 미디어 — 이미지/미디어 타임라인

| 사이트 | 스코프 | 비고 |
|--------|--------|------|
| X/Twitter | **벌크/타임라인 미디어** (게시물 단건 미디어 URL은 twitter.md syndication 경유) | **로그인 쿠키 필수** — 익명 불가 |
| Instagram | 공개 계정 포스트/릴스 | 세션 필요할 수 있음 |
| Tumblr | 공개 블로그 | |

> **X 커버리지 명확화**: twitter.md:54의 syndication API가 이미 트윗 단건 미디어 URL(`tweet.entities.media[].media_url_https`)을 제공한다. gallery-dl X는 **특정 계정의 미디어 전체 타임라인을 벌크 수집**할 때 사용한다.

### 한국 플랫폼

| 사이트 | Extractor | 비고 |
|--------|-----------|------|
| Naver Blog | `NaverBlogPost`, `NaverBlogBlog` | **익명 가능** — 블로그 이미지 추출에 효과적 |
| Naver Webtoon | `NaverWebtoon*` | |
| Kakao | `Kakao*` | |

> Naver Blog는 사실상 익명 성공이 보장되는 거의 유일한 케이스다.
> Pixiv·X 등 다수 사이트는 인증 없이 빈 결과 또는 오류를 반환한다.

### 만화/웹툰

| 사이트 | Extractor |
|--------|-----------|
| MangaDex | `MangaDex*` |
| Webtoon (영문) | `Webtoon*` |
| Komga (자체 호스팅) | `Komga*` |

## 인증 경계

로그인이나 쿠키가 필요한 자료는 이 공개 수집 스킬의 대상이 아니다.
쿠키를 추출·전달하지 않고 접근 제한으로 보고한다.


## Extractor 목록 확인

```bash
# 지원 extractor 목록을 읽어 필요한 공개 사이트 지원 여부를 확인한다.
node .claude/skills/page-fetch/python-runtime.cjs -m gallery_dl --list-extractors
```

## 실용 예시

```bash
# 네이버 블로그 포스트 이미지 URL 목록
gallery-dl -g "https://blog.naver.com/{user}/{post_id}"

# 네이버 블로그 전체 포스트 이미지 메타데이터 (앞 30개)
gallery-dl -j --range "1-30" "https://blog.naver.com/{user}"

```

## 주의사항

- `gallery-dl -j` 이 가장 안전한 범용 명령 (다운로드 없음, 메타데이터만)
- 인증이 필요한 사이트는 쿠키 없이 얻은 공개 결과만 보고하거나 접근 제한으로 종료한다.
- 대형 타임라인(수천 개)은 `--range`로 제한 필수
- `--range`는 1-based 인덱스
