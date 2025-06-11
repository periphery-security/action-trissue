import { Issue, Report } from './dataclass.js'
import { ReportDict } from './interface.js'

export function parseResults(data: ReportDict): Report[] | null {
  try {
    const results = data.Results

    if (!Array.isArray(results)) {
      throw new TypeError(
        `The JSON entry .Results is not a list, got: ${typeof results}`
      )
    }

    const reports: Report[] = []

    for (let idx = 0; idx < results.length; idx++) {
      const result = results[idx]

      if (
        typeof result !== 'object' ||
        result === null ||
        Array.isArray(result)
      ) {
        throw new TypeError(
          `The JSON entry .Results[${idx}] is not a dictionary, got: ${typeof result}`
        )
      }

      if (!('Vulnerabilities' in result)) {
        continue
      }

      const package_type = result['Type']
      const vulnerabilities = result['Vulnerabilities']

      if (!Array.isArray(vulnerabilities)) {
        throw new TypeError(
          `The JSON entry .Results[${idx}].Vulnerabilities is not a list, got: ${typeof vulnerabilities}`
        )
      }

      for (const vulnerability of vulnerabilities) {
        const package_name = vulnerability['PkgName']
        const report_id = `${package_name}-${vulnerability.InstalledVersion}-${vulnerability.VulnerabilityID}`

        const report: Report = {
          id: report_id,
          package: `${package_name}-${vulnerability.InstalledVersion}`,
          package_name: package_name,
          package_version: vulnerability.InstalledVersion,
          package_fixed_version: vulnerability['FixedVersion'] || undefined,
          package_type: package_type,
          target: result['Target'],
          vulnerabilities: [vulnerability]
        }
        reports.push(report)
      }
    }

    return reports.length > 0 ? reports : null
  } catch (e) {
    console.error('Error during parseResults:', e)
    return null
  }
}

export function generateIssues(reports: Report[]): Issue[] {
  const issues: Issue[] = []
  for (const report of reports) {
    const vulnerability = report.vulnerabilities[0]

    // This creates the full, descriptive title you want.
    const issue_title = `${vulnerability.VulnerabilityID}: ${report.package_type} package ${report.package}`

    let issue_body = `## Title\n${vulnerability.Title}\n`
    issue_body += `## Description\n${vulnerability.Description}\n`
    issue_body += `## Severity\n**${vulnerability.Severity}**\n`
    issue_body += `## Fixed in Version\n**${
      report.package_fixed_version || 'No known fix at this time'
    }**\n\n`
    issue_body += `## Primary URL\n${vulnerability.PrimaryURL}\n`
    issue_body += `## Additional Information\n`
    issue_body += `**Vulnerability ID:** ${vulnerability.VulnerabilityID}}\n`
    issue_body += `**Package Name:** ${report.package_name}\n`
    issue_body += `**Package Version:** ${report.package_version}\n`
    const reference_items = vulnerability.References.map(
      (reference: string) => `- ${reference}`
    ).join('\n')
    issue_body += `## References\n${reference_items}\n\n`

    issues.push({
      id: report.id,
      report: report,
      title: issue_title,
      body: issue_body,
      hasFix: report.package_fixed_version !== undefined
    })
  }
  return issues
}
