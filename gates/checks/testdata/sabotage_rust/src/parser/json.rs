//! Synthetic fixture for gates/semgrep/sabotage.yml. NOT REAL CODE.

// sabotage.recursion-without-depth-budget: directly recursive, no depth parameter.
fn parse_value(input: &mut Lexer) -> Value {
    match input.next() {
        Token::ArrayStart => {
            let mut items = Vec::new();
            while !input.at_end() {
                items.push(parse_value(input));
            }
            Value::Array(items)
        }
        t => Value::from(t),
    }
}

// GOOD: the depth budget is threaded through, so nesting cannot outrun the stack.
fn parse_value_bounded(input: &mut Lexer, depth: u32) -> Result<Value, Error> {
    if depth == 0 {
        return Err(Error::TooDeep);
    }
    match input.next() {
        Token::ArrayStart => {
            let mut items = Vec::new();
            while !input.at_end() {
                items.push(parse_value_bounded(input, depth - 1)?);
            }
            Ok(Value::Array(items))
        }
        t => Ok(Value::from(t)),
    }
}
