# Доступность государственных сайтов Молдовы — 13 ноября 2026 г.

Автоматический аудит открытых сайтов зоны `.gov.md`: 9 из 12 хостов ответили и были проверены. Средняя оценка — **70** из 100, полностью без нарушений WCAG — 1 страниц (11%).

## Сводка

| Показатель | Значение |
|---|---|
| Проверено страниц | 9 |
| Не ответили | 3 |
| Средняя оценка | 70 |
| Доступность (axe) | 60 |
| Безопасность заголовков | 67 |
| Мобильная вёрстка | 95 |
| HTTPS | 100% |
| Валидный TLS-сертификат | 78% |
| HSTS | 44% |
| CSP | 22% |
| Указан `lang` | 100% |
| Есть `meta viewport` | 100% |
| Горизонтальная прокрутка на 390 px | 11% |

## Самые проблемные сайты

| # | Сайт | Оценка | Доступность | Нарушений | Критичных |
|---|---|---|---|---|---|
| 1 | [373.gov.md](https://373.gov.md/#/) | 43 | 19 | 8 | 2 |
| 2 | [adma.gov.md](https://adma.gov.md/) | 58 | 44 | 4 | 0 |
| 3 | [aee.gov.md](https://cned.gov.md/ro) | 67 | 53 | 4 | 0 |
| 4 | [admin.particip.gov.md](https://admin-particip.gov.md/login) | 70 | 55 | 5 | 2 |
| 5 | [100.gov.md](https://100.gov.md/) | 75 | 100 | 0 | 0 |
| 6 | [actpermisiv.gov.md](https://actpermisiv.gov.md/#/home) | 76 | 62 | 3 | 1 |
| 7 | [aap.gov.md](https://inamp.gov.md/) | 77 | 69 | 2 | 0 |
| 8 | [actelocale.gov.md](https://actelocale.gov.md/) | 79 | 58 | 4 | 2 |
| 9 | [admin.compensatii.gov.md](https://admin.compensatii.gov.md/ro/auth/login) | 88 | 84 | 2 | 0 |

## Что встречается чаще всего

| Нарушение | Сайтов | Элементов | Уровень |
|---|---|---|---|
| [color-contrast](https://dequeuniversity.com/rules/axe/4.14/color-contrast?application=playwright) — Elements must meet minimum color contrast ratio thresholds | 8 | 105 | серьёзно |
| [link-name](https://dequeuniversity.com/rules/axe/4.14/link-name?application=playwright) — Links must have discernible text | 7 | 30 | серьёзно |
| [label-content-name-mismatch](https://dequeuniversity.com/rules/axe/4.14/label-content-name-mismatch?application=playwright) — Elements must have their visible text as part of their accessible name | 3 | 8 | серьёзно |
| [image-alt](https://dequeuniversity.com/rules/axe/4.14/image-alt?application=playwright) — Images must have alternative text | 2 | 3 | критично |
| [meta-viewport](https://dequeuniversity.com/rules/axe/4.14/meta-viewport?application=playwright) — Zooming and scaling must not be disabled | 2 | 2 | умеренно |
| [aria-allowed-attr](https://dequeuniversity.com/rules/axe/4.14/aria-allowed-attr?application=playwright) — Elements must only use supported ARIA attributes | 2 | 2 | критично |
| [nested-interactive](https://dequeuniversity.com/rules/axe/4.14/nested-interactive?application=playwright) — Interactive controls must not be nested | 1 | 12 | серьёзно |
| [target-size](https://dequeuniversity.com/rules/axe/4.14/target-size?application=playwright) — All touch targets must be 24px large, or leave sufficient space | 1 | 11 | серьёзно |
| [aria-command-name](https://dequeuniversity.com/rules/axe/4.14/aria-command-name?application=playwright) — ARIA commands must have an accessible name | 1 | 2 | серьёзно |
| [label](https://dequeuniversity.com/rules/axe/4.14/label?application=playwright) — Form elements must have labels | 1 | 2 | критично |
| [link-in-text-block](https://dequeuniversity.com/rules/axe/4.14/link-in-text-block?application=playwright) — Links must be distinguishable without relying on color | 1 | 2 | серьёзно |
| [aria-required-children](https://dequeuniversity.com/rules/axe/4.14/aria-required-children?application=playwright) — Certain ARIA roles must contain particular children | 1 | 1 | критично |
| [frame-title](https://dequeuniversity.com/rules/axe/4.14/frame-title?application=playwright) — Frames must have an accessible name | 1 | 1 | серьёзно |
| [select-name](https://dequeuniversity.com/rules/axe/4.14/select-name?application=playwright) — Select element must have an accessible name | 1 | 1 | критично |

## Технические флаги

| Флаг | Сайтов | Что значит |
|---|---|---|
| `no-h1` | 5 | нет заголовка `<h1>` |
| `tls-error` | 2 | ошибка TLS-сертификата |
| `mobile-overflow` | 1 | горизонтальная прокрутка на мобильном |

## Как считалось

- Оценка **доступности**: `100 × e^(−P/100)`, где P — сумма штрафов по правилам axe: 12/6/3/1 балла за критичное, серьёзное, умеренное и мелкое нарушение, умноженные на `1 + log₂(число элементов)`; одно правило даёт не больше 50 баллов штрафа.
- Оценка **безопасности**: HTTPS, валидный сертификат, HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`.
- Оценка **производительности**: число DOM-узлов, вес страницы, количество запросов.
- **Мобильная** оценка: отсутствие горизонтальной прокрутки при ширине 390 px.
- Итог: 50 % доступность, 25 % безопасность, 15 % мобильность, 10 % производительность.

## Ограничения

- Проверяется только главная страница; внутренние разделы могут быть лучше или хуже.
- axe-core находит примерно треть проблем WCAG; ручная проверка (клавиатура, скринридер) не заменяется.
- Часть госсайтов блокирует запросы из дата-центров — такие хосты попадают в «не ответили».
- Оценка — не рейтинг учреждения, а срез одной страницы на дату аудита.

## Данные

- `docs/data/sites.json` — все результаты, `docs/data/site/<host>.json` — детали по сайту.
- Лицензия данных: CC BY 4.0. Код: MIT.
