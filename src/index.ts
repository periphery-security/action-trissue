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

// Helper function to create a stable identifier from an issue title
function getIdentifierFromTitle(title: string): string | null {
  const titleRegex = /^(.*?):.*? package (.*?)-/
  const matches = title.match(titleRegex)
  if (matches && matches.length >= 3) {
    return `${matches[1].toLowerCase()}-${matches[2].toLowerCase()}`
  }
  return null
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
                        by Periphery
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

    const reports = parseResults(reportData)
    const newVulnerabilities = new Map<string, Issue>()
    if (reports) {
      for (const issue of generateIssues(reports)) {
        const identifier = getIdentifierFromTitle(issue.title)
        if (identifier) {
          newVulnerabilities.set(identifier, issue)
        }
      }
    }

    const newVulnIdentifiers = new Set(newVulnerabilities.keys())
    const existingIssueIdentifiers = new Map<string, TrivyIssue>()
    for (const issue of existingTrivyIssues) {
      const identifier = getIdentifierFromTitle(issue.title)
      if (identifier) {
        existingIssueIdentifiers.set(identifier, issue)
      }
    }

    // Close stale issues
    for (const [identifier, issue] of existingIssueIdentifiers.entries()) {
      if (issue.state === 'open' && !newVulnIdentifiers.has(identifier)) {
        if (inputs.dryRun) {
          core.info(
            `[Dry Run] Would close stale issue: #${issue.number} - ${issue.title}`
          )
        } else {
          issuesClosed.push(await github.closeIssue(issue.number))
        }
      }
    }

    // Process new and existing vulnerabilities
    for (const [identifier, issueData] of newVulnerabilities.entries()) {
      const existingIssue = existingIssueIdentifiers.get(identifier)

      if (existingIssue) {
        // Issue exists, check if it's closed and needs reopening
        if (existingIssue.state === 'closed') {
          if (inputs.dryRun) {
            core.info(
              `[Dry Run] Would reopen issue #${existingIssue.number} ('${existingIssue.title}')`
            )
          } else {
            issuesUpdated.push(await github.reopenIssue(existingIssue.number))
          }
        }
      } else {
        // Issue does not exist, create it
        const issueOptionBase: IssueOption & { hasFix: boolean } = {
          title: issueData.title,
          body: issueData.body,
          labels: inputs.issue.labels,
          assignees: inputs.issue.assignees,
          projectId: inputs.issue.projectId,
          enableFixLabel: inputs.issue.enableFixLabel,
          fixLabel: inputs.issue.fixLabel,
          hasFix: issueData.hasFix
        }
        if (inputs.dryRun) {
          core.info(
            `[Dry Run] Would create issue with title: ${issueData.title}`
          )
        } else {
          issuesCreated.push(await github.createIssue(issueOptionBase))
        }
      }
    }

    fixableVulnerabilityExists = Array.from(newVulnerabilities.values()).some(
      (issue) => issue.hasFix
    )

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
