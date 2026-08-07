import { defineEventHandler, createError } from 'h3'
import { config } from '../../../../config/index'

export default defineEventHandler(async (event) => {
    const slugString: string = event.context.params?.slug as any
    if (!slugString) {
        throw createError({ statusCode: 400, statusMessage: 'Missing slug parameter' })
    }
    const slug: string[] = slugString ? slugString.split('/') : []
    if (!slug || Object.keys(slug).length < 2 || Object.keys(slug).length > 2) {
        throw createError({ statusCode: 400, statusMessage: 'Invalid slug' })
    }

    const backendID: any = slug[0]
    const raw: any = slug[1]

    const map = new Map<string, string>(config.NSLookup.map(node => [node.id, node.url]))
    if (!map.has(backendID)) {
        throw createError({ statusCode: 400, statusMessage: 'Invalid backend ID' })
    }
    let apiBaseUrl = map.get(backendID)
    if (apiBaseUrl === undefined) {
        throw createError({ statusCode: 400, statusMessage: 'API base URL not found for the given backend ID' })
    }
    let data: any = {}

    if (apiBaseUrl.slice(-1) != '/') {
        apiBaseUrl = `${apiBaseUrl}/`
    }
    data = await $fetch(`${apiBaseUrl}v1/dnssec/${raw}`, {
        method: 'GET',
        headers: {
            'Origin': config.siteUrl.replace(/\/$/, ''),
        },
    }).catch((error) => {
        console.error(`Error fetching from ${apiBaseUrl}:`, error)
        return {}
    }) || {}
    if (!data || Object.keys(data).length === 0) {
        throw createError({ statusCode: 500, statusMessage: 'Backend error' })
    }

    return data
})
