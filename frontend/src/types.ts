export interface Contact {
  id:   string            // base64-encoded = key in every map
  name: string
  unread: number
  last: string
}

export interface Message {
  id: string
  contactId: string
  text: string
  mine: boolean
  timestamp: Date
}

