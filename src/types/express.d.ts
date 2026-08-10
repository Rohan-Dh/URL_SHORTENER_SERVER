export interface RequesterIdentity {
  id: string;
}

declare global {
  namespace Express {
    interface Request {
      /** Set by requesterIdentity middleware — always present on /api routes. */
      requester?: RequesterIdentity;
    }
  }
}

export {};
