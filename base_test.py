import sys
from antlr4 import *
from parsing.SecLangLexer import SecLangLexer
from parsing.SecLangParser import SecLangParser
from parsing.SecLangParserListener import SecLangParserListener

class Rule:
    def __init__(self):
        pass

class SecLangListener(SecLangParserListener):
    def enterStmt(self, ctx):
        #for m in dir(self):
        #    if m[0:5] == "enter":
        #        print(m)
        print("Entering statement:", ctx.getText())
        #Rule(variables, operators, actions)

    def enterActions_directive(self, ctx):
        print("Entering actions directive:", ctx.getText())

    def enterEngine_config_directive(self, ctx):
        print("Entering engine config directive:", ctx.getText())

    def enterAction(self, ctx:SecLangParser.ActionContext):
        print("Entering action:", ctx.getText())

    def enterAction_with_params_and_args(self, ctx:SecLangParser.ActionContext):
        print("Entering action with params and args:", ctx.getText())

    def enterSetvar_stmnt(self, ctx:SecLangParser.ActionContext):
        print("Entering setvar statement:", ctx.getText())

    def enterSetvar_stmt(self, ctx:SecLangParser.ActionContext):
        print("Entering setvar statement:", ctx.getText())

    def enterAssignment(self, ctx:SecLangParser.ActionContext):
        print("Entering assignment:", ctx.getText())

    def enterValues(self, ctx:SecLangParser.ActionContext):
        print("Entering values:", ctx.getText())

    def enterConfig_value_types(self, ctx:SecLangParser.Config_value_typesContext):
        print("Entering config value:", ctx.getText())

    def enterStmnt_comment(self, ctx):
        print("Entering comment:", ctx.getText())

class MySecLangLexer(SecLangLexer):
    def nextToken(self):
        token = super().nextToken()
        print(f"Recognized Token: {self.symbolicNames[token.type]} - {token.text}")
        return token

    def print_current_state(self):
        print(f"Current Token Type: {self._input.LT(1).type}")

class MySecLangListener(SecLangListener):
    def __init__(self):
        self.rule_stack = []

    def enterEveryRule(self, ctx):
        rule_name = SecLangParser.ruleNames[ctx.getRuleIndex()]
        self.rule_stack.append(rule_name)
        print(f"Entering rule: {self.rule_stack} - '{ctx.getText()}'")

    def exitEveryRule(self, ctx):
        rule_name = SecLangParser.ruleNames[ctx.getRuleIndex()]
        if self.rule_stack and self.rule_stack[-1] == rule_name:
            self.rule_stack.pop()
        print(f"Exiting rule: {self.rule_stack}")

    #def visitTerminal(self, node):
    #    print(f"Terminal: {node.getText()}")

def main(argv):
    debug_lexer = False
    debug_parser = False
    if len(sys.argv) > 1:
        input = FileStream(sys.argv[1], encoding='utf-8')
        if len(sys.argv) > 2:
            for a in sys.argv[2:]:
                if a == "debuglexer":
                    debug_lexer = True
                if a == "debugparser":
                    debug_parser = True
    else:
        input = InputStream(sys.stdin.readline())
    if debug_lexer == True:
        lexer = MySecLangLexer(input)
    else:
        lexer = SecLangLexer(input)
    stream = CommonTokenStream(lexer)

    parser = SecLangParser(stream)
    tree = parser.configuration()
    # walk and print
    if debug_parser == True:
        printer = MySecLangListener()
    else:
        printer = SecLangListener()
    walker = ParseTreeWalker()
    walker.walk(printer, tree)


if __name__ == '__main__':
    main(sys.argv)
