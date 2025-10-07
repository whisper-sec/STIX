package security.whisper.javastix.pattern;

import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.tree.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * STIX Pattern Compiler using ANTLR4.
 *
 * This class provides methods to parse and validate STIX 2.1 pattern expressions
 * using the official OASIS grammar definition.
 *
 * @since 1.2.0
 */
public class StixPatternCompiler {

    private static final Logger logger = LoggerFactory.getLogger(StixPatternCompiler.class);

    /**
     * Result of pattern compilation containing the parsed tree and any errors.
     */
    public static class CompilationResult {
        private final ParseTree parseTree;
        private final List<String> errors;
        private final boolean successful;

        public CompilationResult(ParseTree parseTree, List<String> errors) {
            this.parseTree = parseTree;
            this.errors = errors != null ? errors : new ArrayList<>();
            this.successful = errors == null || errors.isEmpty();
        }

        public ParseTree getParseTree() {
            return parseTree;
        }

        public List<String> getErrors() {
            return errors;
        }

        public boolean isSuccessful() {
            return successful;
        }

        @Override
        public String toString() {
            if (successful) {
                return "Compilation successful";
            } else {
                return "Compilation failed with " + errors.size() + " error(s): " +
                       String.join(", ", errors);
            }
        }
    }

    /**
     * Error listener for collecting parse errors.
     */
    private static class ErrorListener extends BaseErrorListener {
        private final List<String> errors = new ArrayList<>();

        @Override
        public void syntaxError(Recognizer<?, ?> recognizer,
                               Object offendingSymbol,
                               int line,
                               int charPositionInLine,
                               String msg,
                               RecognitionException e) {
            String error = String.format("Line %d:%d - %s", line, charPositionInLine, msg);
            errors.add(error);
            logger.error("Pattern syntax error: {}", error);
        }

        public List<String> getErrors() {
            return errors;
        }

        public boolean hasErrors() {
            return !errors.isEmpty();
        }
    }

    /**
     * Compiles a STIX pattern string into a parse tree.
     *
     * @param pattern The STIX pattern string to compile
     * @return CompilationResult containing the parse tree and any errors
     */
    public CompilationResult compile(String pattern) {
        if (pattern == null || pattern.trim().isEmpty()) {
            List<String> errors = new ArrayList<>();
            errors.add("Pattern cannot be null or empty");
            return new CompilationResult(null, errors);
        }

        logger.debug("Compiling pattern: {}", pattern);

        // Create input stream
        ANTLRInputStream input = new ANTLRInputStream(pattern);

        // Create lexer
        STIXPatternLexer lexer = new STIXPatternLexer(input);

        // Create token stream
        CommonTokenStream tokens = new CommonTokenStream(lexer);

        // Create parser
        STIXPatternParser parser = new STIXPatternParser(tokens);

        // Add error listener
        ErrorListener errorListener = new ErrorListener();
        parser.removeErrorListeners(); // Remove default console error listener
        parser.addErrorListener(errorListener);

        // Parse the pattern
        ParseTree tree = null;
        try {
            tree = parser.pattern();
        } catch (Exception e) {
            logger.error("Failed to parse pattern", e);
            List<String> errors = new ArrayList<>(errorListener.getErrors());
            errors.add("Parse failed: " + e.getMessage());
            return new CompilationResult(null, errors);
        }

        // Check for errors
        if (errorListener.hasErrors()) {
            logger.warn("Pattern compilation completed with errors");
            return new CompilationResult(tree, errorListener.getErrors());
        }

        logger.debug("Pattern compiled successfully");
        return new CompilationResult(tree, null);
    }

    /**
     * Validates a STIX pattern string.
     *
     * @param pattern The STIX pattern string to validate
     * @return true if the pattern is valid, false otherwise
     */
    public boolean isValid(String pattern) {
        CompilationResult result = compile(pattern);
        return result.isSuccessful();
    }

    /**
     * Gets a list of validation errors for a pattern.
     *
     * @param pattern The STIX pattern string to validate
     * @return List of error messages, empty if pattern is valid
     */
    public List<String> validate(String pattern) {
        CompilationResult result = compile(pattern);
        return result.getErrors();
    }

    /**
     * Pretty-prints a parse tree for debugging.
     *
     * @param tree The parse tree to print
     * @return String representation of the tree
     */
    public String prettyPrint(ParseTree tree) {
        if (tree == null) {
            return "null";
        }
        return tree.toStringTree();
    }

    /**
     * Gets the AST (Abstract Syntax Tree) as a string for a pattern.
     *
     * @param pattern The STIX pattern string
     * @return String representation of the AST, or error message if compilation fails
     */
    public String getAST(String pattern) {
        CompilationResult result = compile(pattern);
        if (result.isSuccessful()) {
            return prettyPrint(result.getParseTree());
        } else {
            return "Compilation failed: " + String.join(", ", result.getErrors());
        }
    }
}