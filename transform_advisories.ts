import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { setTimeout } from "node:timers/promises";
import { debug, info, setFailed } from "@actions/core";

interface OSVItem {
  schema_version: "1.7.5";
  id: string;
  published: string;
  modified: string;
  summary: string;
  upstream: string[];
  affected: Array<{
    package: {
      ecosystem: "Nixpkgs";
      name: string;
    };
  }>;
  references: Array<{
    type: "ADVISORY" | "WEB";
    url: string;
  }>;
}

// Subset of the tracker API schema, see https://tracker.security.nixos.org/api/schema/
interface TrackerActivityLogEntry {
  action: string;
  timestamp: string;
  status_value?: string | null;
}

interface TrackerSuggestion {
  cve_id: string;
  title: string;
  description: string | null;
  packages: Record<string, unknown>;
  activity_log: TrackerActivityLogEntry[] | null;
}

interface TrackerIssue {
  code: string;
  title: string;
  created_at: string;
  github_issue_url: string | null;
  suggestions: TrackerSuggestion[];
}

interface TrackerPaginatedIssueList {
  count: number;
  next: string | null;
  results: TrackerIssue[];
}

const USER_AGENT = "nixpkgs-security-advisory-osv-bot";

const ISSUES_API_URL = "https://tracker.security.nixos.org/api/v1/issues";
const ISSUE_CODE_PATTERN = /^NIXPKGS-([0-9]{4})-[0-9]{4,19}$/u;
const SUMMARY_FALLBACK_MAX_WORDS = 10;
const MAX_FETCH_ATTEMPTS = 5;
const DEFAULT_RETRY_DELAY_SECONDS = 60;
const DEFAULT_SYNC_WINDOW_HOURS = 72;
const BASE_DIR_ADVISORIES =
  process.env.ADVISORIES_DIR ?? `${import.meta.dirname}/advisories`;

// Shallow check of the response shape, the tracker API is trusted for the rest
function isTrackerPaginatedIssueList(
  value: unknown,
): value is TrackerPaginatedIssueList {
  return (
    typeof value === "object" &&
    value !== null &&
    "count" in value &&
    typeof value.count === "number" &&
    "next" in value &&
    (value.next === null || typeof value.next === "string") &&
    "results" in value &&
    Array.isArray(value.results)
  );
}

async function fetchIssuesPage(
  page: number,
): Promise<TrackerPaginatedIssueList> {
  const url = new URL(ISSUES_API_URL);
  url.searchParams.set("expand", "suggestions");
  url.searchParams.set("activity_log", "true");
  url.searchParams.set("page", page.toString());

  for (let attempt = 1; ; attempt++) {
    const response = await fetch(url, {
      headers: {
        Accept: "application/json",
        "User-Agent": USER_AGENT,
      },
    });
    if (response.ok) {
      const body: unknown = await response.json();
      if (!isTrackerPaginatedIssueList(body)) {
        throw new TypeError(`Unexpected response body on ${url}`);
      }
      return body;
    }
    if (response.status !== 429 || attempt >= MAX_FETCH_ATTEMPTS) {
      throw new Error(`HTTP error on ${url}, status: ${response.status}`);
    }
    // Only the delay-seconds form of Retry-After is supported, not the HTTP-date one
    const retry_after = response.headers.get("Retry-After")?.trim() ?? "";
    const retry_delay_seconds = /^[0-9]+$/u.test(retry_after)
      ? Number(retry_after)
      : DEFAULT_RETRY_DELAY_SECONDS;
    info(`Rate limited, retrying in ${retry_delay_seconds}s`);
    await setTimeout(retry_delay_seconds * 1000);
  }
}

function toSecondPrecisionISOString(timestamp: number): string {
  const date = new Date(timestamp);
  if (isNaN(date.getTime())) {
    throw new RangeError(`Invalid timestamp: ${timestamp}`);
  }
  // Keep a precision to the second, consistent with previously generated advisories
  date.setUTCMilliseconds(0);
  return date.toISOString();
}

function getPublicationDates(issue: TrackerIssue): {
  published: string;
  modified: string;
} {
  const activity_log = issue.suggestions.flatMap(
    (suggestion) => suggestion.activity_log ?? [],
  );
  // created_at is not reliable for issues migrated from the original tracker,
  // the first time a suggestion has been published is used when available
  const published_timestamps = activity_log
    .filter((entry) => entry.status_value === "published")
    .map((entry) => new Date(entry.timestamp).getTime());
  const published =
    published_timestamps.length > 0
      ? Math.min(...published_timestamps)
      : new Date(issue.created_at).getTime();
  const modified = Math.max(
    published,
    ...activity_log.map((entry) => new Date(entry.timestamp).getTime()),
  );
  return {
    published: toSecondPrecisionISOString(published),
    modified: toSecondPrecisionISOString(modified),
  };
}

function getSummary(issue: TrackerIssue): string {
  const first_suggestion = issue.suggestions[0];
  const title = (issue.title || first_suggestion.title).trim();
  if (title !== "") {
    return title;
  }
  // Same fallback as the tracker web UI: the truncated CVE description
  const description_words = (first_suggestion.description ?? "")
    .trim()
    .split(/\s+/u)
    .filter((word) => word !== "");
  if (description_words.length <= SUMMARY_FALLBACK_MAX_WORDS) {
    return description_words.join(" ");
  }
  return `${description_words.slice(0, SUMMARY_FALLBACK_MAX_WORDS).join(" ")} …`;
}

function transformIssue(issue: TrackerIssue): void {
  const issue_id = issue.code;

  info(`Parsing issue ${issue_id}`);

  const issue_id_match = ISSUE_CODE_PATTERN.exec(issue_id);
  if (issue_id_match === null) {
    throw new Error(`Unexpected issue code format: ${issue_id}`);
  }
  const issue_id_year = issue_id_match[1];

  const advisory_path_base_dir = `${BASE_DIR_ADVISORIES}/${issue_id_year}`;
  const advisory_path = `${advisory_path_base_dir}/${issue_id}.json`;

  if (existsSync(advisory_path)) {
    info(`Issue ${issue_id} has already been parsed, skipping`);
    return;
  }

  if (issue.suggestions.length === 0) {
    throw new Error(`No suggestions found for issue ${issue_id}`);
  }

  const summary = getSummary(issue);
  if (summary === "") {
    throw new Error(`Did not found a summary for issue ${issue_id}`);
  }

  const cve_ids = [
    ...new Set(issue.suggestions.map((suggestion) => suggestion.cve_id)),
  ];
  if (cve_ids.some((cve_id) => !cve_id?.startsWith("CVE-"))) {
    throw new Error(
      `Unexpected CVE references in ${issue_id}: ${cve_ids.join(", ")}`,
    );
  }

  const impacted_packages = [
    ...new Set(
      issue.suggestions.flatMap((suggestion) =>
        Object.keys(suggestion.packages),
      ),
    ),
  ];

  const { published, modified } = getPublicationDates(issue);

  const osv_advisory: OSVItem = {
    schema_version: "1.7.5",
    id: issue_id,
    summary,
    published,
    modified,
    upstream: cve_ids,
    affected: impacted_packages.map(function (impacted_package) {
      return {
        package: {
          ecosystem: "Nixpkgs",
          name: impacted_package,
        },
      };
    }),
    references: [
      {
        type: "ADVISORY",
        url: `http://tracker.security.nixos.org/issues/${issue_id}`,
      },
    ],
  };

  if (issue.github_issue_url !== null && issue.github_issue_url !== "") {
    osv_advisory.references.push({ type: "WEB", url: issue.github_issue_url });
  }

  const osv_advisory_json_str = JSON.stringify(osv_advisory, null, 2);

  debug(osv_advisory_json_str);

  mkdirSync(advisory_path_base_dir, { recursive: true });
  writeFileSync(advisory_path, osv_advisory_json_str);
}

function getSyncWindowHours(): number {
  const sync_window_hours_env = process.env.SYNC_WINDOW_HOURS;
  if (sync_window_hours_env === undefined || sync_window_hours_env === "") {
    return DEFAULT_SYNC_WINDOW_HOURS;
  }
  const sync_window_hours = Number(sync_window_hours_env);
  if (isNaN(sync_window_hours) || sync_window_hours < 0) {
    throw new Error(
      `Invalid SYNC_WINDOW_HOURS value: ${sync_window_hours_env}, expected a positive number`,
    );
  }
  return sync_window_hours;
}

async function fetchAndTransformIssues(
  created_after: Date | null,
): Promise<void> {
  let page = 1;
  while (true) {
    info(`Fetching issues page ${page}`);
    const issues_page = await fetchIssuesPage(page);
    for (const issue of issues_page.results) {
      // Issues are sorted by most recently created first
      if (
        created_after !== null &&
        new Date(issue.created_at) < created_after
      ) {
        info(
          `Issue ${issue.code} has been created before ${created_after.toISOString()}, stopping`,
        );
        return;
      }
      transformIssue(issue);
    }
    if (issues_page.next === null) {
      return;
    }
    page++;
  }
}

try {
  // A sync window of 0 hours means a full synchronization
  const sync_window_hours = getSyncWindowHours();
  const created_after =
    sync_window_hours === 0
      ? null
      : new Date(Date.now() - sync_window_hours * 60 * 60 * 1000);
  await fetchAndTransformIssues(created_after);
} catch (e) {
  setFailed(`Could not fetch and transform issues: ${String(e)}`);
  throw e;
}
