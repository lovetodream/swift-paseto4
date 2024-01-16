public struct Parser<Container: PayloadContainer>: Sendable {
    public typealias Payload = Container.Payload

    public var rules: [Rule]

    public init(rules: [Rule]) {
        self.rules = rules
    }

    public mutating func addRule(_ rule: @escaping Rule) {
        self.rules.append(rule)
    }
}

public extension Parser where Container == Public {
    func verify(_ tainted: String, with key: AsymmetricPublicKey) throws -> Token {
        guard let message = Message<Container>(tainted) else {
            fatalError("TODO: Could not parse PASETO message.")
        }

        let token = try message.verify(with: key)

        try validate(token)

        return token
    }
}

public extension Parser where Container == Local {
    func decrypt(_ tainted: String, with key: SymmetricKey) throws -> Token {
        guard let message = Message<Container>(tainted) else {
            fatalError("TODO: Could not parse PASETO message.")
        }

        let token = try message.decrypt(with: key)

        try validate(token)

        return token
    }
}

public extension Parser {
    func validate(_ token: Token) throws {
        _ = try rules.map({
            switch $0(token) {
            case .pass: return
            case .violation(let error): throw error
            }
        })
    }
}
