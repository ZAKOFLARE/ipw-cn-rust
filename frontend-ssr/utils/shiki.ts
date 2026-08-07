import { codeToHtml } from './shiki.bundle'

export async function highlightCode(code: string, lang: string) {
  try {
    return await codeToHtml(code, { lang, theme: 'github-dark' })
  } catch (error) {
    console.error('Error highlighting code:', error)
    return code
  }
}
