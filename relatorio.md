# Relatório técnico

## 1. Objetivo

Desenvolver um módulo de autenticação para uma startup financeira, com foco em proteção de credenciais e mitigação de ataques comuns relacionados a senhas.

## 2. Decisões adotadas

- Uso de Flask pela simplicidade e aderência ao escopo acadêmico.
- Persistência local em SQLite para manter o projeto executável sem dependências externas.
- Hash de senha com PBKDF2-HMAC-SHA256 e salt único por usuário.
- Separação entre regras de segurança e fluxo de autenticação.

## 3. Mecanismos de segurança implementados

### 3.1 Hash e salt

Cada usuário recebe um salt aleatório gerado com `os.urandom`. A senha não é armazenada em texto puro; apenas o salt e o hash derivado são persistidos.

### 3.2 Política mínima de senha

A senha deve possuir no mínimo 8 caracteres, com letra maiúscula, minúscula, número e caractere especial.

### 3.3 Limite de tentativas

Após 3 falhas consecutivas, a conta é bloqueada temporariamente por 5 minutos.

### 3.4 Registro de logs

Eventos de cadastro, login autorizado, falhas e bloqueios são registrados em arquivo de log.

### 3.5 Validação de força de senha

A própria rotina de cadastro verifica se a senha atende à política mínima antes de permitir o armazenamento.

## 4. Riscos mitigados

- Vazamento de senhas em texto puro.
- Ataques de força bruta.
- Ataques de dicionário.
- Enumeração simples de credenciais por mensagens detalhadas.
- Tentativas repetidas automatizadas.

## 5. Limitações

- A implementação é didática e local.
- Não há MFA real, CAPTCHA real ou integração com serviços externos.
- O endurecimento de sessão pode ser ampliado com CSRF, expiração automática e rate limiting por IP em uma evolução futura.

## 6. Conclusão

A solução atende ao enunciado ao combinar armazenamento seguro de senhas, autenticação com verificação protegida e mecanismos adicionais para aumentar a resistência contra ataques comuns.