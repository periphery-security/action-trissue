import { jest } from '@jest/globals'

// Mock Octokit
const mockOctokit = {
  issues: {
    listForRepo: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    getLabel: jest.fn(),
    createLabel: jest.fn()
  },
  paginate: jest.fn()
}

// Mock modules using unstable_mockModule for ESM
jest.unstable_mockModule('@actions/core', () => ({
  getInput: jest.fn(),
  setOutput: jest.fn(),
  info: jest.fn(),
  startGroup: jest.fn(),
  endGroup: jest.fn(),
  setFailed: jest.fn().mockImplementation((msg) => console.error('setFailed called with:', msg)),
  error: jest.fn()
}))

jest.unstable_mockModule('@actions/github', () => ({
  context: {
    repo: {
      owner: 'owner',
      repo: 'repo'
    }
  }
}))

jest.unstable_mockModule('fs/promises', () => ({
  readFile: jest.fn()
}))

jest.unstable_mockModule('@octokit/rest', () => ({
  Octokit: jest.fn().mockImplementation(() => mockOctokit)
}))

// Import mocked modules
const core = await import('@actions/core')
const fs = await import('fs/promises')
const { main } = await import('../src/index.js')

describe('index.ts main logic', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    
    // Default inputs
    ;(core.getInput as any).mockImplementation((name: string) => {
      switch (name) {
        case 'token': return 'fake-token'
        case 'filename': return '__tests__/trivy-results.json'
        case 'labels': return 'trivy,vulnerability'
        case 'create-labels': return 'true'
        case 'enable-fix-label': return 'true'
        case 'fix-label': return 'fix-available'
        case 'dry-run': return 'false'
        default: return ''
      }
    })
  })

  test('should create a new issue when a vulnerability is found and no existing issue exists', async () => {
    const mockTrivyData = JSON.stringify({
      Results: [{
        Type: 'alpine',
        Target: 'alpine:3.18',
        Vulnerabilities: [{
          VulnerabilityID: 'CVE-2023-0001',
          PkgName: 'openssl',
          InstalledVersion: '3.1.0-r0',
          FixedVersion: '3.1.0-r1',
          Title: 'Test',
          Description: 'Desc',
          Severity: 'HIGH',
          PrimaryURL: 'url',
          References: []
        }]
      }]
    })
    ;(fs.readFile as any).mockResolvedValue(mockTrivyData)

    ;(mockOctokit.paginate as any).mockResolvedValue([])
    ;(mockOctokit.issues.getLabel as any).mockResolvedValue({ data: {} })
    ;(mockOctokit.issues.create as any).mockResolvedValue({
      data: { number: 1, html_url: 'https://github.com/owner/repo/issues/1', title: 'CVE-2023-0001: alpine package openssl-3.1.0-r0' }
    })

    await main()

    expect(mockOctokit.issues.create).toHaveBeenCalled()
    expect(core.setOutput).toHaveBeenCalledWith('fixable_vulnerability', 'true')
  })

  test('should reopen a closed issue if vulnerability is still present', async () => {
    const mockTrivyData = JSON.stringify({
      Results: [{
        Type: 'alpine',
        Target: 'alpine:3.18',
        Vulnerabilities: [{
          VulnerabilityID: 'CVE-2023-0001',
          PkgName: 'openssl',
          InstalledVersion: '3.1.0-r0',
          FixedVersion: '3.1.0-r1',
          Title: 'Test',
          Description: 'Desc',
          Severity: 'HIGH',
          PrimaryURL: 'url',
          References: []
        }]
      }]
    })
    ;(fs.readFile as any).mockResolvedValue(mockTrivyData)

    // Mock GitHub API: One closed issue exists
    ;(mockOctokit.paginate as any).mockResolvedValue([
      {
        number: 1,
        title: 'CVE-2023-0001: alpine package openssl-3.1.0-r0',
        body: 'body',
        state: 'closed',
        labels: ['trivy', 'vulnerability'],
        html_url: 'url'
      }
    ])
    
    ;(mockOctokit.issues.getLabel as any).mockResolvedValue({ data: {} })
    ;(mockOctokit.issues.update as any).mockResolvedValue({
      data: { number: 1, html_url: 'url', title: 'title' }
    })

    await main()

    expect(mockOctokit.issues.update).toHaveBeenCalledWith(expect.objectContaining({
      issue_number: 1,
      state: 'open'
    }))
  })

  test('should close an open issue if vulnerability is no longer present', async () => {
    const mockTrivyData = JSON.stringify({ Results: [] })
    ;(fs.readFile as any).mockResolvedValue(mockTrivyData)

    // Mock GitHub API: One open issue exists
    ;(mockOctokit.paginate as any).mockResolvedValue([
      {
        number: 1,
        title: 'CVE-2023-0001: alpine package openssl-3.1.0-r0',
        body: 'body',
        state: 'open',
        labels: ['trivy', 'vulnerability'],
        html_url: 'url'
      }
    ])
    
    ;(mockOctokit.issues.getLabel as any).mockResolvedValue({ data: {} })
    ;(mockOctokit.issues.update as any).mockResolvedValue({
      data: { number: 1, html_url: 'url', title: 'title' }
    })

    await main()

    expect(mockOctokit.issues.update).toHaveBeenCalledWith(expect.objectContaining({
      issue_number: 1,
      state: 'closed'
    }))
  })
})
