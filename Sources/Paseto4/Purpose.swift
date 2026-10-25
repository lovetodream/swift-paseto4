enum Purpose: String, Sendable {
    case local = "local"
    case `public` = "public"
}

extension Purpose {
    init<P: Payload>(payload: P.Type) {
        switch payload {
        case is Local.Payload.Type: self = .local
        case is Public.Payload.Type: self = .public
        default: fatalError("All implementations must be resolvable")
        }
    }
}
