import * as process from 'process'
import * as fs from 'fs/promises'
import * as core from '@actions/core'
import { generateIssues, parseResults } from './report-generator.js'
import {
  IssueOption,
  IssueResponse,
  ReportDict,
  TrivyIssue
} from './interface.js'
import { GitHub } from './github.js'
import { Inputs } from './inputs.js'
import { Issue } from './dataclass.js'

function abort(message: string, error?: Error): never {
  console.error(`Error: ${message}`)
  if (error) {
    console.error(error)
  }
  process.exit(1)
}

// Helper function to create a stable identifier from an issue title or report
function getIdentifier(source: Issue | TrivyIssue): string | null {
  let title: string
  if ('title' in source) {
    title = source.title
  } else {
    // This case is for the initial creation from a report
    const vulnerability = source.report.vulnerabilities[0]
    title = `${vulnerability.VulnerabilityID}: ${source.report.package_type} package ${source.report.package}`
  }

  // Stricter regex: Only matches titles with a version number indicated by a hyphen.
  const titleRegex = /^(.*?):.*? package (.*?)-/
  const matches = title.match(titleRegex)
  if (matches && matches.length >= 3) {
    return `${matches[1].toLowerCase()}-${matches[2].toLowerCase()}`
  }
  return null // Will return null for older, non-conforming titles
}

async function main() {
  // Print the custom ASCII art logo
  console.log(String.raw`
  _______ _____
 |__   __|_   _|
    | |_ __| |  ___ ___ _   _  ___
    | | '__| | / __/ __| | | |/ _ \
    | | | _| |_\__ \__ \ |_| |  __/
    |_|_||_____|___/___/\__,_|\___|
                        by Periphery 1.1.3
`)

  const inputs = new Inputs()
  const github = new GitHub(inputs.token)

  const issuesCreated: IssueResponse[] = []
  const issuesUpdated: IssueResponse[] = []
  const issuesClosed: IssueResponse[] = []
  let fixableVulnerabilityExists = false

  try {
    if (inputs.issue.createLabels) {
      const labelsToCreate = [...inputs.issue.labels]
      if (inputs.issue.enableFixLabel && inputs.issue.fixLabel) {
        labelsToCreate.push(inputs.issue.fixLabel)
      }
      for (const label of labelsToCreate) {
        if (inputs.dryRun) {
          core.info(`[Dry Run] Would create label: ${label}`)
        } else {
          await github.createLabelIfMissing(label)
        }
      }
    }

    const trivyRaw = await fs.readFile(inputs.issue.filename, 'utf-8')
    const reportData = JSON.parse(trivyRaw) as ReportDict
    const existingTrivyIssues: TrivyIssue[] = await github.getTrivyIssues(
      inputs.issue.labels
    )
    const reports = parseResults(reportData) // Simplified call

    // Map all new vulnerabilities by their stable identifier
    const newVulnerabilities = new Map<string, Issue>()
    if (reports) {
      for (const issue of generateIssues(reports)) {
        const identifier = getIdentifier(issue)
        if (identifier) {
          newVulnerabilities.set(identifier, issue)
        }
      }
    }

    core.info('--- Existing Issues ---')
    for (const existingIssue of existingTrivyIssues) {
      const identifier = getIdentifier(existingIssue)
      core.info(
        `Issue #${existingIssue.number}: '${existingIssue.title}' (Identifier: ${identifier})`
      )
    }

    core.info('\n--- New Vulnerabilities ---')
    for (const [identifier, issue] of newVulnerabilities.entries()) {
      core.info(`Vulnerability: '${issue.title}' (Identifier: ${identifier})`)
    }

    // Process existing issues: close stale ones, re-open active ones
    for (const existingIssue of existingTrivyIssues) {
      const identifier = getIdentifier(existingIssue)
      if (!identifier) continue

      const vulnerabilityIsStillPresent = newVulnerabilities.has(identifier)
      core.info(
        `\nProcessing issue #${existingIssue.number} ('${existingIssue.title}') with identifier '${identifier}'...`
      )
      core.info(
        `Vulnerability still present in report: ${vulnerabilityIsStillPresent}`
      )

      if (vulnerabilityIsStillPresent) {
        // The vulnerability is still in the scan.
        if (existingIssue.state === 'closed') {
          // If the issue is closed, re-open it.
          if (inputs.dryRun) {
            core.info(
              `[Dry Run] Would reopen issue #${existingIssue.number} ('${existingIssue.title}')`
            )
          } else {
            issuesUpdated.push(await github.reopenIssue(existingIssue.number))
          }
        }
        // Mark this vulnerability as handled so we don't create a new issue for it.
        newVulnerabilities.delete(identifier)
      } else if (existingIssue.state === 'open') {
        // If the issue is open, close it.
        if (inputs.dryRun) {
          core.info(
            `[Dry Run] Would close stale issue: #${existingIssue.number} - ${existingIssue.title}`
          )
        } else {
          issuesClosed.push(await github.closeIssue(existingIssue.number))
        }
      }
    }

    core.info('\n--- Creating new issues for remaining vulnerabilities ---')
    // Create issues for any remaining (genuinely new) vulnerabilities
    for (const newIssue of newVulnerabilities.values()) {
      const issueOption: IssueOption & { hasFix: boolean } = {
        title: newIssue.title,
        body: newIssue.body,
        labels: inputs.issue.labels,
        assignees: inputs.issue.assignees,
        projectId: inputs.issue.projectId,
        enableFixLabel: inputs.issue.enableFixLabel,
        fixLabel: inputs.issue.fixLabel,
        hasFix: newIssue.hasFix
      }
      if (inputs.dryRun) {
        core.info(`[Dry Run] Would create issue with title: ${newIssue.title}`)
      } else {
        issuesCreated.push(await github.createIssue(issueOption))
      }
    }

    // Determine if any fixable vulnerabilities exist at the end
    const finalReports = parseResults(reportData)
    fixableVulnerabilityExists = finalReports
      ? finalReports.some((r) => r.package_fixed_version)
      : false

    core.setOutput(
      'fixable_vulnerability',
      fixableVulnerabilityExists.toString()
    )
    core.setOutput('created_issues', JSON.stringify(issuesCreated))
    core.setOutput('closed_issues', JSON.stringify(issuesClosed))
    core.setOutput('updated_issues', JSON.stringify(issuesUpdated))
  } catch (error) {
    if (error instanceof Error) {
      abort(`Error: ${error.message}`, error)
    } else {
      abort(`Error: An unknown error occurred. ${error}`)
    }
  }
}

main()
