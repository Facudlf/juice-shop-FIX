/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { BasketItemModel } from '../models/basketitem'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'

function validateQuantity () {
  return (req: Request, res: Response, next: NextFunction) => {
    const quantity = Number(req.body.quantity) // Usamos Number() para ser más estrictos

    // isNaN(quantity) comprueba si la entrada no es un número (ej: "1-4")
    // quantity < 1 comprueba si es negativo o cero
    if (isNaN(quantity) || quantity < 1) {
      return res.status(400).json({ status: 'error', message: 'Invalid quantity.' })
    }

    if (quantity > 5) {
      challengeUtils.solveIf(challenges.basketManipulateChallenge, () => true)
      return res.status(400).json({ status: 'error', message: 'You can order only up to 5 items of a product.' })
    }
    
    next()
  }
}

export const quantityCheckBeforeBasketItemAddition = validateQuantity
export const quantityCheckBeforeBasketItemUpdate = validateQuantity

export function getBasketItem () {
  return (req: Request, res: Response, next: NextFunction) => {
    BasketItemModel.findOne({ where: { id: req.params.id } })
      .then((basketItem) => {
        res.status(200).json({ status: 'success', data: basketItem })
      })
      .catch((error: Error) => {
        next(error)
      })
  }
}

export function addBasketItem () {
  return (req: Request, res: Response, next: NextFunction) => {
    const basketId = req.body.BasketId
    const productId = req.body.ProductId
    const quantity = Number(req.body.quantity) // Aseguramos que es un número

    BasketItemModel.findOne({ where: { ProductId: productId, BasketId: basketId } }).then((item) => {
      if (item) {
        // --- LA CORRECCIÓN CLAVE ---
        // Sumamos dos números, nunca un número y un string.
        const newQuantity = Number(item.quantity) + quantity
        
        // Re-validamos la nueva cantidad total
        if (newQuantity > 5) {
            challengeUtils.solveIf(challenges.basketManipulateChallenge, () => true)
            return res.status(400).json({ status: 'error', message: 'You can order only up to 5 items of a product.' })
        }

        item.update({ quantity: newQuantity }).then((updatedItem) => {
          res.status(200).json({ status: 'success', data: updatedItem })
        }).catch((error: Error) => {
          next(error)
        })
      } else {
        BasketItemModel.create({
          ProductId: productId,
          BasketId: basketId,
          quantity: quantity
        }).then((newBasketItem) => {
          res.status(200).json({ status: 'success', data: newBasketItem })
        }).catch((error: Error) => {
          next(error)
        })
      }
    }).catch((error: Error) => {
      next(error)
    })
  }
}

export function deleteBasketItem () {
  return (req: Request, res: Response, next: NextFunction) => {
    BasketItemModel.destroy({ where: { id: req.params.id } }).then(() => {
      res.status(200).json({ status: 'success', data: 'Deleted successfully' })
    }).catch((error: Error) => {
      next(error)
    })
  }
}

export function updateBasketItem () {
  return (req: Request, res: Response, next: NextFunction) => {
    BasketItemModel.findOne({ where: { id: req.params.id } }).then(item => {
      if (item) {
        const quantity = Number(req.body.quantity) // Aseguramos que es número
        item.update({ quantity }).then(updatedItem => {
          res.status(200).json({ status: 'success', data: updatedItem })
        }).catch((error: Error) => {
          next(error)
        })
      } else {
        res.status(404).send({ status: 'error', message: 'Not found' })
      }
    }).catch((error: Error) => {
      next(error)
    })
  }
}