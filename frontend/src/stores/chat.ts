import { reactive, ref } from 'vue'
import { defineStore } from 'pinia'
import {
  GetContacts, GetMessages, SendMessage
} from '../../wailsjs/go/main/App'
import type {
  Contact, Message
} from '../types'

export const useChat = defineStore('chat', () => {

  /* ───────── state ───────── */
  const contacts = ref<Contact[]>([])
  const messages = reactive<Record<string, Message[]>>({})

  /* ───────── actions ─────── */
  async function loadContacts() {
    const list = await GetContacts()
    contacts.value = list.map(c => ({
      id: c.id,
      name: c.name,
      unread: 0,
      last: ''
    }))
  }

  async function loadHistory(contactId: string) {
    const raw = await GetMessages(contactId, 0)

    messages[contactId] = raw.map((m: any) => {
      // Date-String → Date-Objekt
      const ts = typeof m.at === 'string'
        ? new Date(m.at)            // ISO-String → Date
        : new Date(Number(m.at) / 1e6) // Fallback, falls du später Zahl sendest

      return {
        id: m.id,
        contactId,
        text: m.text,
        mine: m.out,
        timestamp: ts
      }
    })
  }
  async function send(id: string, text: string) {
    console.debug('[Pinia] send()', { id, text })
    try {
      await SendMessage(id, text)
    } catch (e) {
      console.error('[Pinia] backend error', e)
      throw e
    }
  }

  return { contacts, messages, loadContacts, loadHistory, send }
})
