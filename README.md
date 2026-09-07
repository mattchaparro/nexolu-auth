# nexolu-auth

Identidad para el ecosistema Nexolú. `auth.nexolu.co`.

## De dónde sale

Este servicio se decidió como sección **§4.G del plan de la tienda online**
—«Identidad: invitado en el MVP, `auth.nexolu.co` como servicio aparte»—, no
como una idea suelta.

La decisión que lo libera es la de la tienda: el MVP cobra **como invitado**,
sin cuentas de comprador. Por eso este servicio no está en el camino crítico
de la tienda y puede arrancar cuando se quiera. El propio §4.G cierra diciendo
que esto merece su propio plan; este repo es donde vive.

Se ve el eco de esa decisión en el código de la tienda, en
`nexolu-store-front/src/services/api.ts`: las rutas de storefront son anónimas
por diseño, y el comentario deja anotado que si algún día hace falta identidad
de comprador, va contra `auth.nexolu.co` y no contra la API pública del POS.

## Las tres audiencias, en orden

| Audiencia | Veredicto | Cuándo |
|---|---|---|
| Personal interno | El mejor primer consumidor: hay dolor real hoy | Primero |
| Compradores finales | Terreno virgen | Segundo |
| Staff de los negocios | Riesgo alto, beneficio bajo hoy | Después del cutover |

El orden no es de dificultad técnica sino de dolor: el personal interno ya
sufre el problema, los compradores todavía no tienen nada que romper, y el
staff de los negocios es el único grupo con sesiones en producción que se
pueden dañar — por eso va al final, después del cutover.

## Métodos de acceso

Decididos en §4.G:

- **OTP por WhatsApp**, primero. El canal ya está resuelto por `nexolu-comms-api`.
- **Contraseña + TOTP** para el personal interno.

## SSO del superadmin sin romper el desacople

Darle SSO al superadmin es lo que más fácil acopla todo el ecosistema a este
servicio. §4.G lo permite bajo tres condiciones, y son las tres a la vez:

1. El droplet de producción queda protegido por `_NEVER_POWER_CYCLE`.
2. **Verificación local, emisión remota**: `auth.nexolu.co` emite, pero cada
   consumidor verifica de su lado con la llave pública. Nadie queda esperando
   una ida y vuelta a este servicio para resolver un request.
3. `ADMIN_EMAIL` + `ADMIN_PASSWORD_HASH` como *break-glass*, para que este
   servicio caído no deje a nadie fuera de su propio panel.

La segunda condición es la que define la forma del token: si la verificación
es local con llave pública, este servicio no puede estar en el camino crítico
de cada request de cada producto.

## Alcance

Este servicio se queda con **quién eres**. Los permisos por producto se quedan
donde están: los de agenda en `nexolu-spa-api`, los de caja en `nexolu-pos-api`,
cada uno con su `spatie/laravel-permission`. Centralizar también la
autorización volvería esto el cuello de botella de todo el ecosistema.

Fuera, y no por ahora sino por diseño: los enlaces por token de reserva,
encuesta y lista de espera del spa. Identifican una cita, no a una persona;
no son cuentas y no pasan por aquí.

## Estado

Sin código. Tres fases previstas; **falta escribir el plan detallado de la
Fase 1**, que es el siguiente paso real de este repo.

Abierto, para resolver en ese plan:

- **Stack.** Los servicios core (`nexolu-ia-core`, `nexolu-comms-api`,
  `nexolu-payments-core`) son Python; los productos (`pos`, `spa`) son Laravel.
- **Qué método entra en qué fase.** §4.G deja OTP por WhatsApp como primer
  método y contraseña + TOTP para el personal interno, que es la primera
  audiencia. Cuál de los dos abre la Fase 1 no está escrito.
- **Migración.** Qué pasa con los `users` que hoy tiene cada API por su cuenta,
  y cómo se consolidan las cuentas duplicadas de un mismo dueño.
