# Segurança da API — I-Stock Manager (DDA Metalúrgica)

**Escopo:** API REST `/v1` para controlar o estoque de pastilhas industriais. Este documento registra as decisões de segurança que orientarão a implementação com Spring Security.

## 1. Matriz de Segurança

| Recurso/operação | Ameaça ou vulnerabilidade | Possível impacto | Controle preventivo adotado |
|---|---|---|---|
| `POST /auth/login` (a criar) | Força bruta, enumeração de contas, roubo de credenciais | Acesso indevido ao estoque e às operações | Respostas genéricas para credenciais inválidas; limitação progressiva de tentativas; HTTPS; registro de eventos sem registrar senhas ou tokens; emissão de token curto após autenticação. |
| Credenciais e contas | Senhas em texto puro, reutilização ou exposição de segredo | Comprometimento de contas e acesso persistente | Armazenar somente hash adaptativo BCrypt (ou Argon2); nunca registrar/devolver senha; segredos e chaves fora do código-fonte; provisionamento controlado de contas e troca/revogação de credenciais. |
| `GET /pastilhas`, `GET /pastilhas/{id}` | Exposição de informações operacionais; acesso sem autenticação | Divulgação de catálogo, níveis e disponibilidade de estoque | Exigir autenticação `OPERADOR` ou `ADMINISTRADOR`; validar parâmetros e retornar somente campos necessários. |
| `POST /pastilhas`, `PUT /pastilhas/{id}` | Acesso não autorizado, IDOR, atribuição em massa e validação insuficiente | Alteração indevida do catálogo ou dos limites de estoque | Restringir a `ADMINISTRADOR`; autorização no endpoint/serviço; DTOs de entrada com campos explicitamente permitidos; validar formato, tamanho, obrigatoriedade, IDs e valores não negativos. |
| `GET /movimentacoes` | Exposição do histórico operacional e possível acesso indevido a outros registros | Divulgação de consumo, lotes e atividade interna | Exigir `OPERADOR` ou `ADMINISTRADOR`; validar filtros `pastilha_id` e `tipo`; limitar/paginar resultados ao implementar a API. |
| `POST /movimentacoes` | Falsificação do autor, quantidade inválida, repetição da requisição e concorrência | Histórico falso, saldo incorreto ou estoque negativo | Exigir `OPERADOR` ou `ADMINISTRADOR`; identificar o autor pelo principal autenticado (não confiar em `usuario` do JSON); validar quantidade positiva, tipo e existência da pastilha; exigir chave de idempotência por requisição e, para chave já processada, devolver o resultado original sem repetir a movimentação; aplicar atualização de saldo, gravação do histórico e registro da chave em transação atômica, com controle de concorrência e regra para impedir saldo negativo. |
| `GET /alertas` e filtro `em_alerta` | Acesso indevido e parâmetros malformados | Exposição do estado de estoque ou consultas inesperadas | Exigir `OPERADOR` ou `ADMINISTRADOR`; aceitar apenas booleano válido e aplicar consultas parametrizadas. |
| Consultas e filtros em todos os endpoints | SQL Injection | Leitura, alteração ou exclusão de dados no banco | Usar consultas parametrizadas/repositórios Spring Data ou ORM; nunca concatenar entrada em SQL; validar e limitar filtros. |
| Campos textuais (`descricao`, `fabricante`, `motivo`) e respostas | XSS armazenado/refletido em clientes que exibem os dados | Execução de conteúdo malicioso no sistema web consumidor | Validar tamanho e formato; responder como JSON com `Content-Type` correto; codificar conteúdo no contexto de saída no frontend; não inserir valores como HTML confiável. A API não substitui a codificação de saída da interface. |
| Autenticação baseada em token e requisições de escrita | CSRF, caso credenciais sejam enviadas automaticamente pelo navegador | Operações realizadas usando sessão da vítima | Usar API stateless com token Bearer no cabeçalho `Authorization`, sem autenticação por cookie; nesse modelo, desabilitar CSRF no Spring Security. Se a implementação migrar para cookies/sessão, habilitar proteção CSRF e `SameSite` antes de liberar escrita. |
| Todas as rotas acessadas por navegador | CORS permissivo ou configuração incorreta | Site externo lê respostas ou induz chamadas a partir de origens não previstas | Permitir somente origens HTTPS conhecidas do frontend; restringir métodos e cabeçalhos necessários; não combinar origem `*` com credenciais; CORS não é mecanismo de autenticação. |
| Token e endpoints protegidos | Token roubado, expirado ou privilégios excessivos | Uso da conta até a revogação/expiração | Validar assinatura, emissor, audiência e expiração; tokens de acesso de curta duração; transportar somente em HTTPS; não colocar token em URL ou logs; política de revogação/renovação definida na implementação. |
| Erros, logs e documentação | Vazamento de detalhes, segredos ou dados internos | Facilitação de ataques e exposição de informações | Respostas de erro sem stack trace, SQL ou segredos; logs de auditoria de login e mudanças de estoque sem credenciais/tokens; restringir documentação/health detalhado ao ambiente interno. |
| Tráfego e disponibilidade da API | Interceptação, abuso automatizado e negação de serviço | Roubo de dados ou indisponibilidade | HTTPS obrigatório em produção; limites de tamanho de requisição, timeout, paginação e rate limiting; monitorar falhas e volume de requisições. |

## 2. Plano de Segurança da API

### Autenticação

A API será stateless e usará Spring Security com autenticação por token Bearer JWT. Será disponibilizado `POST /auth/login` para validar usuário e senha e emitir token assinado, com expiração curta e papéis do usuário. Tokens serão enviados no cabeçalho `Authorization: Bearer <token>` e validados em cada chamada protegida. A API não terá cadastro público de usuários; contas serão provisionadas por processo administrativo. Em produção, todo o tráfego usará HTTPS.

### Recursos públicos e protegidos

- **Público:** `POST /auth/login`; endpoints estritamente técnicos de disponibilidade poderão ser públicos, sem detalhes internos. A documentação OpenAPI poderá ser pública apenas se aprovada para o ambiente; caso contrário, será restrita.
- **Protegido:** todas as rotas de estoque existentes: `/pastilhas`, `/pastilhas/{id}`, `/movimentacoes` e `/alertas`.
- Não haverá rota pública para cadastro de conta. A especificação atual não define exclusão de pastilha; se uma rota de exclusão for adicionada, será exclusiva de `ADMINISTRADOR` e deverá preservar a integridade do histórico de movimentações.

### Perfis e permissões

| Recurso/operação | Público (sem autenticação) | `OPERADOR` | `ADMINISTRADOR` |
|---|---:|---:|---:|
| `POST /auth/login` | Sim | Sim | Sim |
| Consultar pastilhas (`GET /pastilhas`, `GET /pastilhas/{id}`) | Não | Sim | Sim |
| Cadastrar pastilha (`POST /pastilhas`) | Não | Não | Sim |
| Alterar cadastro/estoque mínimo (`PUT /pastilhas/{id}`) | Não | Não | Sim |
| Consultar movimentações (`GET /movimentacoes`) | Não | Sim | Sim |
| Registrar entrada/saída (`POST /movimentacoes`) | Não | Sim | Sim |
| Consultar alertas (`GET /alertas`) | Não | Sim | Sim |
| Excluir pastilha | Não disponível na API descrita | Não | Não disponível; se criada, somente administrador |
| Gerenciar contas e papéis | Não | Não | Sim, por processo controlado |

`OPERADOR` executa o trabalho diário de consulta e registro de movimentações, sem alterar o catálogo ou as regras de estoque mínimo. `ADMINISTRADOR` pode executar as operações do operador, manter o cadastro das pastilhas e gerenciar contas e papéis.

### Autorização

As permissões serão aplicadas por padrão de rota e método HTTP no Spring Security e reforçadas na camada de serviço para operações de escrita. A política padrão será negar qualquer rota não explicitamente permitida. A aplicação verificará o papel associado ao usuário autenticado; o cliente não poderá escolher o próprio papel nem atribuir outro autor à movimentação. Como os recursos descritos são compartilhados pela empresa, não há isolamento por proprietário individual nesta versão.

### Proteção de credenciais e dados

Senhas serão armazenadas apenas como hash BCrypt com fator de custo apropriado (ou Argon2, se adotado no projeto), nunca descriptografadas ou devolvidas pela API. Chaves de assinatura JWT e credenciais de banco serão fornecidas por configuração segura do ambiente/gerenciador de segredos, fora do repositório. O campo `usuario` aceito hoje em `NovaMovimentacao` deverá ser removido do contrato de entrada ou ignorado: o autor será preenchido no servidor a partir do usuário autenticado, mantendo a trilha de auditoria confiável.

### CORS, CSRF e transporte

CORS permitirá somente a origem exata do frontend autorizado em produção e as origens locais necessárias no desenvolvimento, com métodos e cabeçalhos mínimos (`Authorization`, `Content-Type`). Não será usada origem curinga com credenciais. Como a autenticação será por Bearer token enviado explicitamente e não por cookie, a API stateless poderá desabilitar CSRF; essa decisão deverá ser revista se passar a usar cookies ou sessão. HTTPS será obrigatório em produção.

### Validação, erros e operação segura

As entradas serão validadas por DTOs e Bean Validation; os dados serão acessados por consultas parametrizadas. O `POST /movimentacoes` exigirá uma chave de idempotência única por operação. A chave e o resultado da operação serão persistidos atomicamente com a movimentação; uma repetição com a mesma chave retornará o resultado já registrado sem alterar saldo ou histórico novamente. Reutilizar a chave com conteúdo diferente será rejeitado. Operações de movimentação e atualização do saldo serão atômicas, com controle de concorrência e validação de saldo suficiente. Respostas não exporão stack traces nem detalhes do banco. Haverá logs de auditoria para autenticação e operações que alteram catálogo ou saldo, sem incluir senhas, tokens ou dados sensíveis desnecessários. A implementação também limitará tentativas de login e volume/tamanho de requisições.
