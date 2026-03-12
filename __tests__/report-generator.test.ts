import { parseResults, generateIssues, getIdentifier } from '../src/report-generator.js'
import { ReportDict } from '../src/interface.js'

describe('report-generator', () => {
  const mockData: ReportDict = {
    Results: [
      {
        Type: 'os-pkg',
        Target: 'alpine:3.18',
        Vulnerabilities: [
          {
            VulnerabilityID: 'CVE-2023-1234',
            PkgName: 'libc',
            InstalledVersion: '1.0',
            FixedVersion: '1.1',
            Title: 'Vulnerability in libc',
            Description: 'A vulnerability in libc',
            Severity: 'HIGH',
            PrimaryURL: 'https://example.com/CVE-2023-1234',
            References: ['https://example.com/ref1']
          }
        ]
      }
    ]
  }

  test('parseResults should parse valid data', () => {
    const reports = parseResults(mockData)
    expect(reports).toHaveLength(1)
    expect(reports![0].package_name).toBe('libc')
    expect(reports![0].vulnerabilities[0].VulnerabilityID).toBe('CVE-2023-1234')
  })

  test('generateIssues should yield issues', () => {
    const reports = parseResults(mockData)!
    const issues = Array.from(generateIssues(reports))
    expect(issues).toHaveLength(1)
    expect(issues[0].title).toContain('CVE-2023-1234')
    expect(issues[0].hasFix).toBe(true)
  })

  test('getIdentifier should return correct identifier for Issue', () => {
    const reports = parseResults(mockData)!
    const issues = Array.from(generateIssues(reports))
    const identifier = getIdentifier(issues[0])
    expect(identifier).toBe('cve-2023-1234-libc')
  })

  test('getIdentifier should return correct identifier for TrivyIssue', () => {
    const trivyIssue = {
      number: 1,
      title: 'CVE-2023-1234: os-pkg package libc-1.0',
      body: 'body',
      state: 'open',
      labels: [],
      html_url: ''
    }
    const identifier = getIdentifier(trivyIssue)
    expect(identifier).toBe('cve-2023-1234-libc')
  })

  test('getIdentifier should return null for non-conforming title', () => {
    const trivyIssue = {
      number: 1,
      title: 'Old Title Format',
      body: 'body',
      state: 'open',
      labels: [],
      html_url: ''
    }
    const identifier = getIdentifier(trivyIssue)
    expect(identifier).toBeNull()
  })
})
