/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const reviewId = req.body.id;
    const user = security.authenticatedUsers.from(req) // vuln-code-snippet vuln-line forgedReviewChallenge

    // --- INICIO DE LA MITIGACIÓN ---
    // 1. Validar que el ID sea un string y no un objeto.
    if (typeof reviewId !== 'string') {
      return res.status(400).json({ error: 'Invalid input format for ID.' });
    }

    // 2. (Defensa en profundidad) Un update por ID no debe ser 'multi'.
    const options = { multi: false };
    // --- FIN DE LA MITIGACIÓN ---

    db.reviewsCollection.update(
      { _id: reviewId }, // Ahora 'reviewId' es un string seguro
      { $set: { message: req.body.message } },
      options // Se usa la opción segura
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        challengeUtils.solveIf(challenges.noSqlReviewsChallenge, () => { return result.modified > 1 }) // vuln-code-snippet hide-line
        challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return user?.data && result.original[0] && result.original[0].author !== user.data.email && result.modified === 1 }) // vuln-code-snippet hide-line
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
// vuln-code-snippet end noSqlReviewsChallenge forgedReviewChallenge
