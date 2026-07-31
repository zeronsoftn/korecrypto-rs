//! CAVP .req/.sam 파일 파서.
//!
//! `.sam` 파일은 응답 템플릿으로, 요청 필드와 함께 답을 채울 자리가 `= ?` 로
//! 표시되어 있다. 본 파서는 파일을 줄 단위 항목(`Item`)으로 보존하여, `?` 만
//! 계산값으로 치환한 뒤 원래 서식 그대로 `.rsp` 로 다시 출력할 수 있게 한다.

/// 한 줄을 나타내는 항목.
#[derive(Clone, Debug)]
pub enum Item {
    /// 빈 줄.
    Blank,
    /// 주석(`#...`) 또는 대괄호 헤더(`[...]`) 등 비필드 줄(원문 보존).
    Raw(String),
    /// `KEY = VALUE` 형태의 필드. `query` 가 참이면 값이 `?` 였던 항목.
    Field {
        key: String,
        value: String,
        query: bool,
    },
}

/// 파일을 `Item` 목록으로 파싱한다.
pub fn parse(text: &str) -> Vec<Item> {
    let mut items = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.trim().is_empty() {
            items.push(Item::Blank);
            continue;
        }
        // 대괄호 헤더/주석은 원문 보존.
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with('[') {
            items.push(Item::Raw(line.to_string()));
            continue;
        }
        // `KEY = VALUE` 분해 (첫 '=' 기준).
        if let Some(eq) = line.find('=') {
            let key = line[..eq].trim().to_string();
            let value = line[eq + 1..].trim().to_string();
            // 값에 '?' 가 포함되면 채울 자리("?", "? or Invalid" 등).
            let query = value.contains('?');
            items.push(Item::Field { key, value, query });
        } else {
            items.push(Item::Raw(line.to_string()));
        }
    }
    items
}

/// `Item` 목록을 `.rsp` 텍스트로 직렬화한다(원래 서식: `KEY = VALUE`).
pub fn serialize(items: &[Item]) -> String {
    let mut out = String::new();
    for item in items {
        match item {
            Item::Blank => {}
            Item::Raw(s) => out.push_str(s),
            Item::Field { key, value, .. } => {
                out.push_str(key);
                out.push_str(" = ");
                out.push_str(value);
            }
        }
        out.push('\n');
    }
    out
}

/// 레코드: 연속된 필드 줄 묶음을 가리키는 항목 인덱스 모음.
/// (빈 줄/주석/헤더로 구분된다.)
pub type Record = Vec<usize>;

/// 필드 줄들이 빈 줄/Raw 로 구분되는 레코드 단위 인덱스 목록을 만든다.
pub fn records(items: &[Item]) -> Vec<Record> {
    let mut recs = Vec::new();
    let mut cur: Record = Vec::new();
    for (i, it) in items.iter().enumerate() {
        match it {
            Item::Field { .. } => cur.push(i),
            _ => {
                if !cur.is_empty() {
                    recs.push(std::mem::take(&mut cur));
                }
            }
        }
    }
    if !cur.is_empty() {
        recs.push(cur);
    }
    recs
}

/// 레코드 안에서 특정 키의 값을 찾는다(첫 일치).
pub fn get<'a>(items: &'a [Item], rec: &Record, key: &str) -> Option<&'a str> {
    for &i in rec {
        if let Item::Field { key: k, value, .. } = &items[i] {
            if k == key {
                return Some(value.as_str());
            }
        }
    }
    None
}

use std::collections::BTreeMap;

/// 레코드 목록을 만들되, 각 레코드 위치에서 활성화된 섹션 헤더(`[K = V]`)를
/// 함께 반환한다. CAVP 파일은 여러 `[...]` 섹션으로 나뉘고 각 섹션의
/// 파라미터(TagLen, Iteration, RLEN 등)가 그 뒤 레코드들에 적용된다.
/// 헤더는 최근값 우선으로 누적된다.
pub fn records_with_sections(items: &[Item]) -> Vec<(Record, BTreeMap<String, String>)> {
    let mut out = Vec::new();
    let mut cur: Record = Vec::new();
    let mut section: BTreeMap<String, String> = BTreeMap::new();
    let flush = |cur: &mut Record,
                 section: &BTreeMap<String, String>,
                 out: &mut Vec<(Record, BTreeMap<String, String>)>| {
        if !cur.is_empty() {
            out.push((std::mem::take(cur), section.clone()));
        }
    };
    for (i, it) in items.iter().enumerate() {
        match it {
            Item::Field { .. } => cur.push(i),
            Item::Raw(s) => {
                // `[K = V]` 섹션 헤더 파싱.
                let t = s.trim();
                if let Some(inner) = t.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
                    if let Some(eq) = inner.find('=') {
                        section.insert(
                            inner[..eq].trim().to_string(),
                            inner[eq + 1..].trim().to_string(),
                        );
                    }
                }
                flush(&mut cur, &section, &mut out);
            }
            Item::Blank => flush(&mut cur, &section, &mut out),
        }
    }
    flush(&mut cur, &section, &mut out);
    out
}

/// 레코드 안 특정 키 필드 줄 전체를 Raw 텍스트로 교체한다(예: 복호 실패 시
/// `PT = ? or Invalid` 줄을 `Invalid` 한 줄로 치환). 성공 시 true.
pub fn set_raw(items: &mut [Item], rec: &Record, key: &str, raw: &str) -> bool {
    for &i in rec {
        if let Item::Field { key: k, .. } = &items[i] {
            if k == key {
                items[i] = Item::Raw(raw.to_string());
                return true;
            }
        }
    }
    false
}

/// 레코드 안에서 같은 키의 모든 값을 등장 순서대로 모은다.
pub fn get_all<'a>(items: &'a [Item], rec: &Record, key: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    for &i in rec {
        if let Item::Field { key: k, value, .. } = &items[i] {
            if k == key {
                out.push(value.as_str());
            }
        }
    }
    out
}

/// 레코드 안 특정 키 필드의 값을 설정하고 query 플래그를 해제한다.
/// 성공 시 true. (같은 키가 여러 개면 첫 query 항목을 채운다.)
pub fn set(items: &mut [Item], rec: &Record, key: &str, val: &str) -> bool {
    // 우선 query 인 동일 키를 찾는다.
    for &i in rec {
        if let Item::Field {
            key: k,
            value,
            query,
        } = &mut items[i]
        {
            if k == key && *query {
                *value = val.to_string();
                *query = false;
                return true;
            }
        }
    }
    // 없으면 일반 동일 키.
    for &i in rec {
        if let Item::Field {
            key: k,
            value,
            query,
        } = &mut items[i]
        {
            if k == key {
                *value = val.to_string();
                *query = false;
                return true;
            }
        }
    }
    false
}

/// 레코드 안에서 키 없이 정해진 텍스트(예: "VALID or INVALID")인 Raw 줄을
/// 찾아 다른 텍스트로 치환한다. 성공 시 true.
pub fn replace_raw(items: &mut [Item], rec: &Record, contains: &str, val: &str) -> bool {
    // rec 은 Field 인덱스만 담으므로, rec 범위 직후의 Raw 줄까지 탐색한다.
    let start = *rec.first().unwrap_or(&0);
    let end = (*rec.last().unwrap_or(&0) + 2).min(items.len());
    for it in items.iter_mut().take(end).skip(start) {
        if let Item::Raw(s) = it {
            if s.contains(contains) {
                *s = val.to_string();
                return true;
            }
        }
    }
    false
}
