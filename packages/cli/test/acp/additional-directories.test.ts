import { describe, expect, test } from "bun:test"
import type { PermissionRule } from "@opencode/client/promise"
import { makeSession, rpcError, startWire, type Wire } from "./wire-fixture"

const grant = (directory: string): PermissionRule => ({
  action: "external_directory",
  resource: `${directory}/**`,
  effect: "allow",
})

const other: PermissionRule[] = [
  { action: "read", resource: "*.secret", effect: "deny" },
  { action: "external_directory", resource: "/shared/lib/private/*", effect: "deny" },
]

const updates = (acp: Wire) =>
  acp.server.requests.filter((request) => request.method === "PATCH" && request.path.startsWith("/api/session/"))

describe("acp additional directories over the wire", () => {
  test("initialize advertises additional directories", async () => {
    await using acp = await startWire()

    const result = await acp.initialize()

    expect(result.agentCapabilities?.sessionCapabilities?.additionalDirectories).toEqual({})
  })

  test("session/new grants normalized unique directories other than cwd and lists them", async () => {
    await using acp = await startWire()
    await acp.initialize()

    const created = await acp.request("session/new", {
      cwd: "/workspace",
      additionalDirectories: ["/shared/lib/", "/workspace", "/docs/../product-docs", "/shared/lib", "/workspace/"],
      mcpServers: [],
    })

    expect(acp.server.sessions.get(created.sessionId)?.permissions).toEqual([
      grant("/shared/lib"),
      grant("/product-docs"),
    ])
    expect((await acp.request("session/list", { cwd: "/workspace" })).sessions).toEqual([
      expect.objectContaining({
        sessionId: created.sessionId,
        additionalDirectories: ["/shared/lib", "/product-docs"],
      }),
    ])
  })

  test.each(["shared/lib", "", "/shared/*", "/shared/lib?"])(
    "rejects %p before creating a session",
    async (directory) => {
      await using acp = await startWire()
      await acp.initialize()

      expect(
        await rpcError(
          acp.request("session/new", {
            cwd: "/workspace",
            additionalDirectories: ["/shared/ok", directory],
            mcpServers: [],
          }),
        ),
      ).toMatchObject({ code: -32602, data: { additionalDirectory: directory } })
      expect(acp.server.sessions.size).toBe(0)
    },
  )

  test("load and resume replace ACP grants with the requested list and keep other session rules", async () => {
    await using acp = await startWire()
    acp.server.sessions.set("ses_saved", {
      ...makeSession("ses_saved"),
      permissions: [grant("/old"), ...other],
    })
    await acp.initialize()

    await acp.request("session/load", {
      cwd: "/workspace",
      sessionId: "ses_saved",
      additionalDirectories: ["/shared/lib", "/product-docs"],
      mcpServers: [],
    })
    expect(acp.server.sessions.get("ses_saved")?.permissions).toEqual([
      grant("/shared/lib"),
      grant("/product-docs"),
      ...other,
    ])

    await acp.request("session/resume", {
      cwd: "/workspace",
      sessionId: "ses_saved",
      additionalDirectories: ["/shared/lib", "/product-docs"],
    })
    expect(updates(acp)).toHaveLength(1)

    await acp.request("session/resume", { cwd: "/workspace", sessionId: "ses_saved" })
    expect(acp.server.sessions.get("ses_saved")?.permissions).toEqual(other)
    expect((await acp.request("session/list", { cwd: "/workspace" })).sessions[0]).not.toHaveProperty(
      "additionalDirectories",
    )
  })

  test("forks replace inherited grants with the requested list", async () => {
    await using acp = await startWire()
    acp.server.sessions.set("ses_source", { ...makeSession("ses_source"), permissions: [grant("/old"), ...other] })
    await acp.initialize()

    const plain = await acp.request("session/fork", { cwd: "/workspace", sessionId: "ses_source" })
    const granted = await acp.request("session/fork", {
      cwd: "/workspace",
      sessionId: "ses_source",
      additionalDirectories: ["/shared/lib"],
    })

    expect(acp.server.sessions.get(plain.sessionId)?.permissions).toEqual(other)
    expect(acp.server.sessions.get(granted.sessionId)?.permissions).toEqual([grant("/shared/lib"), ...other])
    expect(acp.server.sessions.get("ses_source")?.permissions).toEqual([grant("/old"), ...other])
  })

  test("leaves session permissions alone without additional directories", async () => {
    await using acp = await startWire()
    acp.server.sessions.set("ses_saved", { ...makeSession("ses_saved"), permissions: other })
    await acp.initialize()

    const created = await acp.request("session/new", { cwd: "/workspace", mcpServers: [] })
    await acp.request("session/load", { cwd: "/workspace", sessionId: "ses_saved", mcpServers: [] })
    await acp.request("session/resume", { cwd: "/workspace", sessionId: "ses_saved", additionalDirectories: [] })

    const create = acp.server.requests.find((request) => request.method === "POST" && request.path === "/api/session")
    expect(create?.body).not.toHaveProperty("permissions")
    expect(acp.server.sessions.get(created.sessionId)?.permissions).toBeUndefined()
    expect(acp.server.sessions.get("ses_saved")?.permissions).toEqual(other)
    expect(updates(acp)).toEqual([])
  })
})
