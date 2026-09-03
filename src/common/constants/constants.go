package constants

// InternalOrg is the frozen organization identifier used in all path constructions.
// It mirrors project_org at creation time and must never change on disk (AI.md PART 2).
const InternalOrg = "apimgr"

// InternalName is the frozen binary/service name used in all path constructions.
// It mirrors project_name at creation time and must never change on disk (AI.md PART 2).
const InternalName = "caswhois"

// RepoURL is the project's source repository, used in the default application
// footer (AI.md PART 16 — Footer Customization → Default Application Footer).
const RepoURL = "https://github.com/apimgr/whois"
