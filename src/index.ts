import * as process from 'process'
import * as fs from 'fs/promises' // Use promises for async file reading
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

async function main() {
  // Print the custom ASCII art logo
  console.log(`
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

    const reports = parseResults(reportData, existingTrivyIssues)
    const newVulnerabilities = new Map<string, Issue>()

    if (reports) {
      for (const issue of generateIssues(reports)) {
        const identifier = `${issue.report.vulnerabilities[0].VulnerabilityID.toLowerCase()}-${issue.report.package_name.toLowerCase()}`
        newVulnerabilities.set(identifier, issue)
      }
    }

    for (const existingIssue of existingTrivyIssues) {
      const match = existingIssue.title.match(/^(.*?):/)
      if (!match || !match[1]) continue

      const identifier = match[1].toLowerCase()

      if (newVulnerabilities.has(identifier)) {
        const newIssueData = newVulnerabilities.get(identifier)!
        if (existingIssue.state === 'closed') {
          if (inputs.dryRun) {
            core.info(
              `[Dry Run] Would reopen issue #${existingIssue.number} ('${existingIssue.title}')`
            )
          } else {
            issuesUpdated.push(await github.reopenIssue(existingIssue.number))
          }
        }
        newVulnerabilities.delete(identifier)
      } else {
        if (existingIssue.state === 'open') {
          if (inputs.dryRun) {
            core.info(
              `[Dry Run] Would close stale issue: #${existingIssue.number} - ${existingIssue.title}`
            )
          } else {
            issuesClosed.push(await github.closeIssue(existingIssue.number))
          }
        }
      }
    }

    for (const newIssue of newVulnerabilities.values()) {
      const issueOptionBase: IssueOption & { hasFix: boolean } = {
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
        core.info(
          `[Dry Run] Would create issue with title: ${newIssue.title}`
        )
      } else {
        issuesCreated.push(await github.createIssue(issueOptionBase))
      }
    }

    fixableVulnerabilityExists =
      issuesCreated.some((i) =>
        newVulnerabilities.get(i.title.toLowerCase())?.hasFix
      ) ||
      existingTrivyIssues.some(
        (i) => i.state === 'open' && i.labels.includes(inputs.issue.fixLabel!)
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