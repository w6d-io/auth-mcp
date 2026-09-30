import type { ToolDef } from '../registry.js'
import { identityTools, makeCanI } from './identity.js'
import { siteTools } from './sites.js'
import { iamTools } from './iam.js'
import { orgTools } from './orgs.js'
import { accessTools } from './access.js'
import { auditTools } from './audit.js'
import { siteWriteTools } from './site-writes.js'
import { siteOnboardingTools } from './site-onboarding.js'
import { siteImportTools } from './site-import.js'
import { sitePublishTools } from './site-publish.js'
import { userWriteTools } from './user-writes.js'
import { bulkTools } from './bulk.js'
import { groupWriteTools } from './group-writes.js'
import { draftTools } from './drafts.js'

/** Read wave (W3): wired to jinbe's existing endpoints. */
export const readTools: ToolDef[] = [...identityTools, ...siteTools, ...iamTools, ...orgTools, ...accessTools, ...auditTools]

/**
 * Write wave: direct writes, decided by jinbe (owner rules in write-common.ts). diff_site and
 * get_bulk_job read, but sit with the writes they serve.
 */
export const writeTools: ToolDef[] = [...siteWriteTools, ...siteOnboardingTools, ...siteImportTools, ...sitePublishTools, ...userWriteTools, ...groupWriteTools, ...bulkTools]

/** Stubs, see drafts.ts. */
export const stubTools: ToolDef[] = draftTools

/** Answers about the whole list, so built from it (lazily: it is part of it). */
export const canI: ToolDef = makeCanI(() => allTools) as ToolDef

export const allTools: ToolDef[] = [...readTools, canI, ...writeTools, ...stubTools]
