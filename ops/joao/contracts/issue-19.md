# Issue #19 — current executable contract

This is the single current contract, consolidated on 2026-10-20 under issue #21.
Historical issue comments preserve decisions and evidence; superseded instructions
in those comments do not override this contract. Portuguese below preserves the
owner-approved acceptance criteria.

## Current stage: consent preparation and independent review

- Work only in the existing João #19 worktree/session, preserving commit d46034c and
  every existing diff/receipt. Do not commit, push or deliver the entire issue during
  this preparation. The wrapper recognizes this opt-in stage and reviews it independently.
- Complete the two review findings from issuecomment-6292297252: handle consent
  completing after an agent response without falsely rewriting that response as success;
  prove per-scanner successful status and full comparable coverage, not name matching.
- Exercise real runner event ordering with a fake transport, late consent, timeout,
  cancellation, denied/unavailable host approval, wrong tenant/operation/computer/folder,
  and the applicable second-analysis handoff. Inspect the public rerun contract.
- A separate real no-model proof must use the same coordinator, official runtime,
  authenticated public UI and synthetic target. Reuse existing proof for typed-status
  verification if possible. A helper alone is not proof of AI remediation.
- Preserve provenance: sequence 4 consulted score 42 and 19 findings; it did not complete
  AI remediation or a new AI rerun. Do not attribute technical preparation to AI.
- Run proportional checks and leave reviewable changes. Finish with a concise summary
  of changes, deterministic tests, real evidence, limits and cleanup. The wrapper will
  run checks and independent review; do not request chat review as an intermediate gate.
- Correct technical failures within the authorized laboratory scope. Offline work must
  proceed despite expired OAuth. For actual expiry, use the versioned bounded official
  recovery helper in the installed laboratory ops/joao directory. Do not repeat a
  successful login or change account, scopes, trust, sandbox or credentials.
- A pass in preparation only means ready to request the next campaign. It does not
  satisfy the full acceptance criteria below and cannot mark #19 or #17 done.

## Current authorizations and target

- Candidate: HML v0.81.0, source 45f83d2581e6986fa8825e8a1c00c2093d61c4bb.
  Verify published public metadata before using it; do not silently substitute a version.
- Existing receipt chain: original 20261016, extension-1 20261016, extension-2 20261019.
  Six total starts authorized; four CLI/Linux consumed; zero of two IDE/Windows used.
  Maximum 600 seconds per start. Failed starts count. No fifth CLI, quota reset,
  alternative provider, or IDE-reserve consumption during preparation.
- Wrapper development/review is not a remediation test. No turn/start of a test model
  may occur in preparation or review. Use existing CLI subscription, never an API key.
- Official OAuth recovery in the same isolated laboratory account and six existing
  scopes, client/agent update through official verified artifacts, synthetic PTY/public
  UI consent and exact host-path/UID1654 readability checks are already authorized.
- Preserve the host channel and exact physical folder identity. No new VM, Docker
  installation, data reset, product edit/publication or security-review bypass.
- Human IDE acceptance remains separate; Linux over SSH does not prove native Windows.

## Full acceptance (unchanged, not satisfied by preparation)

## Objetivo

Validar de forma independente a jornada entregue pela Rappor Security #286: de uma ferramenta de IA real, analisar a pasta atual, consultar a orientação de um Problema, corrigir apenas um projeto sintético e comprovar o resultado numa nova análise e na Web.

Executor: João, exclusivamente no repositório `rappor-security-lab`. O proprietário autorizou em 2026-10-03 preparar a continuidade sequencial pelos agentes. Não alterar, integrar ou publicar o produto.

## Dependências e disparo

- `renersilv/rappor-security#286` entregue e publicada com SHA e versão visível verificados pelo wrapper.
- Issue #18 deste laboratório entregue com o runner da VM Windows existente, atualizado para o contrato MSIX corrente.
- Selecionar o SHA, a versão e a origem exatos do candidato em um registro sanitizado antes de executar. Nenhum teste usa implicitamente a última versão disponível.
- Esta tarefa permanece `blocked` por dependência até essas condições. Não depende das jornadas Supabase/Vercel das Issues #16/#17 e não as implementa.

## Fonte de verdade e fronteira

Ler AGENTS.md, docs/STATUS.md, docs/BENCHMARK-CONTRACT.md, docs/SAFETY.md e os contratos públicos publicados do cliente/MCP. A implementação da #286 deve produzir seu próprio aceite antes desta validação independente; este relatório não substitui testes de produto ausentes.

Uma conexão MCP remota e OAuth oficial. O cliente local é o mesmo para ferramentas de IA compatíveis; não criar plugin, endpoint ou script especial por marca. Não usar chave de API da OpenAI. Usar somente autenticação já disponível e autorizada; se um login humano for indispensável, registrar a única ação concreta, sem pedir ou publicar segredo.

## Jornada obrigatória

1. Verificar saúde, SHA e versão visível; registrar versões de sistema, IA, cliente oficial, agente, scanners e baseline do corpus.
2. Usar ao menos um host CLI e um host IDE reais, cobrindo Linux e Windows x64. Verificar descoberta ou instalação oficial em perfil isolado, autorização no navegador e retorno ao host. Não contam chamadas diretas ao SDK ou respostas simuladas.
3. Pedir à IA que analise o projeto atual. O usuário escolhe **Pela Rappor** ou **Neste computador**, sem redigitar caminho, criar ZIP, copiar token ou configurar segundo MCP.
4. **Pela Rappor:** confirmar localmente cada envio, executar Semgrep/Gitleaks/Trivy e verificar resultado Web. Alterar arquivo ainda não enviado ao Git e provar novo snapshot no rerun.
5. **Neste computador:** autorizar a pasta no cliente instalado, comprovar leitura pelo agente do computador exato, rerun sobre arquivos atuais e remoção da montagem ao término. O código não vai para o control plane.
6. A IA lê a orientação de um Problema, corrige o corpus artificial e repete a mesma configuração/revisão. As verificações funcionais do corpus passam; os achados corrigidos desaparecem com cobertura comparável e completa.
7. Conferir na Web renderizada o mesmo score, cobertura, Problemas e histórico consultados pela IA. Guardar evidência visual sanitizada para o proprietário.
8. Preservar e exercitar as entradas Web atuais: ZIP gerenciado e pasta pelo seletor nativo. Git público continua somente gerenciado.
9. Exercitar negativa/cancelamento, OAuth revogado, cliente/runtime indisponível e pasta movida de modo limitado. Verificar orientação útil, ausência de configuração falsa, credencial exposta ou montagem persistente.

## Corpus, resultados e segurança

- Ground truth independente, casos positivos e negativos, estado vulnerável/fixo/reintroduzido quando aplicável e verificações funcionais. Somente segredos sintéticos não funcionais.
- Não transformar saída do scanner em expectativa. Sete achados e score 57,77→100 foram evidência anterior de um corpus específico, não valores universais deste gate.
- Falha, cobertura parcial ou scanner indisponível nunca significa análise limpa. Mudança de scanner/regra/base de vulnerabilidades exige baseline separado.
- Nenhum caminho físico, código, token, callback OAuth completo, credencial ou log bruto em MCP, Git, Issues, relatório público ou screenshots.
- Não copiar código interno do produto para o laboratório. Consumir somente artefatos oficiais e contratos públicos; acesso local à VM não autoriza alterar o produto.

## Recursos e limites

- Usar somente `joao-windows-x64`, já existente. Não criar VM, baixar ISO, recriar disco, resetar Windows ou duplicar Docker. Preservar a instalação existente e as evidências.
- Uma carga pesada por vez; não executar junto com build/regressão do Raimundo ou Zeca. Aplicar timeout e cleanup a cada etapa.
- Homologação e prévia são alvos distintos. Publicação não autoriza reset de banco. Nenhuma operação em produção, conta real de cliente ou submissão Store.
- Não alterar requisito de segurança ou descartar teste para obter sucesso. Pré-requisito externo ausente deve ser declarado com precisão.

## Entrega e retorno aos executores

- Relatório sanitizado por SHA/versão, matriz de jornadas com `Passed`, `Failed`, `BlockedByConsent` ou `Inconclusive`, versões, tempos, comparação esperado/observado e cleanup confirmado.
- `Passed` exige todos os critérios desta tarefa; sem substituir cliente real por harness ou aceite visual por chamadas HTTP.
- Falha reproduzível gera Issue pequena no produto, vinculada a este relatório. Segurança, Windows, MCP, comportamento e ambiguidades: `executor:raimundo`. Somente apresentação Web dentro do allowlist: `executor:zeca`. Exatamente um executor e um estado por Issue.
- O proprietário autoriza essas correções estritamente necessárias para concluir a #286, preservados os limites desta tarefa. Novas capacidades e mudanças de produto fora desse contrato exigem decisão própria.
- Cada correção deve indicar reprodução e verificação de retorno. Evitar duplicatas e não iniciar ciclo infinito João↔Raimundo. Seguir o limite de retentativas do wrapper; se a mesma falha persistir, preservar evidência e informar a condição concreta.
- `npm test` e `npm run check` passam antes de `validating`. O wrapper integra somente o laboratório. A conclusão técnica não substitui o aceite manual do proprietário.

## Não objetivos

Gate global de provedores das Issues #16/#17, nova infraestrutura, conta paga, nova VM, certificado/Store, prova ARM64 sem hardware, automação de correção de código de clientes e integração/publicação do produto pelo João.
