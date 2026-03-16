import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import * as cheerio from "cheerio";
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

const USER_AGENT = "nixpkgs-security-advisory-osv-bot";

const BASE_ISSUES_PAGE_URL = "https://tracker.security.nixos.org/issues/?page=";
const BASE_DIR_ADVISORIES = `${import.meta.dirname}/advisories`;

async function fetchAndParseIssues(
  current_page: number = 1,
  initial_max_page: number | null = null,
): Promise<void> {
  const response = await fetch(`${BASE_ISSUES_PAGE_URL}${current_page}`, {
    headers: {
      "User-Agent": USER_AGENT,
    },
  });
  if (!response.ok) {
    throw new Error(`HTTP error, status: ${response.status}`);
  }
  const html = await response.text();
  const $root = cheerio.load(html);

  let max_page: number = initial_max_page ?? 1;
  if (initial_max_page === null) {
    max_page = parseInt(
      $root("#pagination").find("a").last().text().trim(),
      10,
    );
  }

  const $issues = $root('article[id^="issue-NIXPKGS-"]');

  for (const issue_element of $issues) {
    const issue_id = issue_element.attribs.id.replace("issue-", "");

    info(`Parsing issue ${issue_id}`);

    const issue_id_year = issue_id.split("-", 2)[1];

    const advisory_path_base_dir = `${BASE_DIR_ADVISORIES}/${issue_id_year}`;
    const advisory_path = `${advisory_path_base_dir}/${issue_id}.json`;
    if (existsSync(advisory_path)) {
      info(`Issue ${issue_id} has already been parsed, skipping`);
      continue;
    }

    const $issue_element = $root(issue_element);

    const summary = $issue_element.find(".heading").first().text().trim();
    if (summary === "") {
      throw new Error(`Did not found a summary for issue ${issue_id}`);
    }

    const github_issue_link_elements = $issue_element.find(
      'a[href^="https://github.com/NixOS/nixpkgs/issues/"]',
    );
    if (github_issue_link_elements.length > 1) {
      throw new Error(
        `Found ${github_issue_link_elements.length} GH link in ${issue_id}, expected 1 or 0`,
      );
    }
    const github_issue_link = github_issue_link_elements[0]?.attribs.href ?? "";

    const cve_id_reference = $issue_element
      .find('a[href^="https://nvd.nist.gov/vuln/detail/CVE-"]')
      .text()
      .trim();
    const nb_cve_id_references_found = (cve_id_reference.match(/CVE-/g) || [])
      .length;
    if (nb_cve_id_references_found !== 1) {
      throw new Error(
        `Found ${nb_cve_id_references_found} CVE references in ${issue_id}, expected 1`,
      );
    }

    const activity_log_published_date_text = $issue_element
      .find(".activity-log-entry-timestamp")
      .last()
      .attr("data-timestamp-iso");
    if (activity_log_published_date_text === undefined) {
      throw new Error(`Publication date not found for issue ${issue_id}`);
    }
    const activity_log_published_date = new Date(
      activity_log_published_date_text,
    );

    const impacted_packages = [];

    for (const active_package_element of $root(
      $issue_element.find('div[id$="-active-packages"]').children(),
    )) {
      const package_name = $root(active_package_element)
        .find("a")
        .first()
        .text()
        .trim();
      if (package_name === "") {
        continue;
      }
      impacted_packages.push(package_name);
    }

    const osv_advisory: OSVItem = {
      schema_version: "1.7.5",
      id: issue_id,
      summary,
      published: activity_log_published_date.toISOString(),
      modified: activity_log_published_date.toISOString(),
      upstream: [cve_id_reference],
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

    if (github_issue_link !== "") {
      osv_advisory.references.push({ type: "WEB", url: github_issue_link });
    }

    const osv_advisory_json_str = JSON.stringify(osv_advisory, null, 2);

    debug(osv_advisory_json_str);

    mkdirSync(advisory_path_base_dir, { recursive: true });
    writeFileSync(advisory_path, osv_advisory_json_str);
  }

  if (current_page < max_page) {
    await fetchAndParseIssues(current_page + 1, max_page);
  }
}

try {
  await fetchAndParseIssues();
} catch (e) {
  setFailed(`Could not fetch and parse issues: ${e}`);
  throw e;
}
