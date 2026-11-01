/**
 * z-security API client：走 /z-team/api/security/** 面（编排：process / policies / policy 台账）。
 */
import {createRequest} from '@yuku123/z-frontend-common'

const request = createRequest({baseURL: '', tokenKey: 'zsecurity_token'})

export default request

export function configureSecurity(config) {
    if (config && config.apiBase !== undefined) {
        request.defaults.baseURL = config.apiBase
    }
}

export const securityApi = {
    process: (payload) => request.post('/z-team/api/security/process', payload),
    trace: (traceId) => request.get(`/z-team/api/security/trace/${encodeURIComponent(traceId)}`),
    policies: (scene) => request.get('/z-team/api/security/policies', {params: scene ? {scene} : {}}),
    scenes: () => request.get('/z-team/api/security/scenes'),
    published: () => request.get('/z-team/api/security/policy/published'),
    ledger: (policyId) => request.get('/z-team/api/security/policy/ledger', {params: {policyId}}),
    health: () => request.get('/api/security/health'),
}
