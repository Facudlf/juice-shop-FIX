/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import * as models from '../models/index'
import { UserModel } from '../models/user'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

class ErrorWithParent extends Error {
  parent: Error | undefined
}

// Código SEGURO: Usando Parámetros de Reemplazo para sanitizar el input
export function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)

    // 1. Definimos la consulta SQL cruda (Raw Query)
    //    Usamos un marcador de posición llamado :criteria en lugar de concatenar el string.
    const rawQuery = `SELECT * FROM Products 
                      WHERE (
                        (name LIKE :criteria OR description LIKE :criteria) 
                        AND deletedAt IS NULL
                      ) 
                      ORDER BY name`
                      
    // 2. Ejecutamos la consulta pasando el input del usuario en el objeto 'replacements'.
    //    Sequelize se encarga de escapar y sanitizar el input antes de ejecutar la consulta.
    models.sequelize.query(rawQuery, {
      replacements: {
        criteria: `%${criteria}%` // El input se pasa como dato, no como código SQL.
      }
    })
      .then(([products]: any) => {
        const dataString = JSON.stringify(products)
        
        // --- Lógica de OWASP Juice Shop para resolver los desafíos (se mantiene sin cambios) ---
        if (challengeUtils.notSolved(challenges.unionSqlInjectionChallenge)) {
          let solved = true
          UserModel.findAll().then(data => {
            const users = utils.queryResultToJson(data)
            if (users.data?.length) {
              for (let i = 0; i < users.data.length; i++) {
                solved = solved && utils.containsOrEscaped(dataString, users.data[i].email) && utils.contains(dataString, users.data[i].password)
                if (!solved) {
                  break
                }
              }
              if (solved) {
                challengeUtils.solve(challenges.unionSqlInjectionChallenge)
              }
            }
          }).catch((error: Error) => {
            next(error)
          })
        }
        if (challengeUtils.notSolved(challenges.dbSchemaChallenge)) {
          let solved = true
          void models.sequelize.query('SELECT sql FROM sqlite_master').then(([data]: any) => {
            const tableDefinitions = utils.queryResultToJson(data)
            if (tableDefinitions.data?.length) {
              for (let i = 0; i < tableDefinitions.data.length; i++) {
                if (tableDefinitions.data[i].sql) {
                  solved = solved && utils.containsOrEscaped(dataString, tableDefinitions.data[i].sql)
                  if (!solved) {
                    break
                  }
                }
              }
              if (solved) {
                challengeUtils.solve(challenges.dbSchemaChallenge)
              }
            }
          })
        } 
        // ---------------------------------------------------------------------------------------

        for (let i = 0; i < products.length; i++) {
          products[i].name = req.__(products[i].name)
          products[i].description = req.__(products[i].description)
        }
        res.json(utils.queryResultToJson(products))
      }).catch((error: ErrorWithParent) => {
        next(error.parent)
      })
  }
}