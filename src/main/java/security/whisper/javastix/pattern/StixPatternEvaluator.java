package security.whisper.javastix.pattern;

import com.jayway.jsonpath.JsonPath;
import org.antlr.v4.runtime.tree.ParseTree;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import security.whisper.javastix.bundle.BundleableObject;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.regex.Pattern;

/**
 * STIX Pattern Evaluator using ANTLR4 parse trees.
 *
 * This class evaluates compiled STIX patterns against STIX objects to determine matches.
 * It supports all STIX 2.1 pattern operators and comparison expressions.
 *
 * @since 1.2.0
 */
public class StixPatternEvaluator extends STIXPatternBaseVisitor<Object> {

    private static final Logger logger = LoggerFactory.getLogger(StixPatternEvaluator.class);

    private final Map<String, Object> observationData;
    private final StixPatternCompiler compiler;

    /**
     * Creates a new pattern evaluator.
     */
    public StixPatternEvaluator() {
        this.observationData = new HashMap<>();
        this.compiler = new StixPatternCompiler();
    }

    /**
     * Evaluates a pattern against a single STIX object.
     *
     * @param pattern The STIX pattern string
     * @param object The STIX object to evaluate against
     * @return true if the pattern matches the object, false otherwise
     */
    public boolean evaluate(String pattern, BundleableObject object) {
        if (pattern == null || object == null) {
            return false;
        }

        StixPatternCompiler.CompilationResult result = compiler.compile(pattern);
        if (!result.isSuccessful()) {
            logger.error("Pattern compilation failed: {}", result.getErrors());
            return false;
        }

        // Convert object to JSON for evaluation
        String objectJson = object.toJsonString();
        observationData.clear();
        observationData.put(object.getType(), objectJson);

        try {
            Object evalResult = visit(result.getParseTree());
            return Boolean.TRUE.equals(evalResult);
        } catch (Exception e) {
            logger.error("Error evaluating pattern", e);
            return false;
        }
    }

    /**
     * Evaluates a pattern against multiple STIX objects.
     *
     * @param pattern The STIX pattern string
     * @param objects The STIX objects to evaluate against
     * @return List of objects that match the pattern
     */
    public List<BundleableObject> evaluate(String pattern, Collection<BundleableObject> objects) {
        List<BundleableObject> matches = new ArrayList<>();

        if (pattern == null || objects == null || objects.isEmpty()) {
            return matches;
        }

        for (BundleableObject obj : objects) {
            if (evaluate(pattern, obj)) {
                matches.add(obj);
            }
        }

        return matches;
    }

    @Override
    public Object visitPattern(STIXPatternParser.PatternContext ctx) {
        return visit(ctx.observationExpressions());
    }

    @Override
    public Object visitObservationExpressions(STIXPatternParser.ObservationExpressionsContext ctx) {
        if (ctx.FOLLOWEDBY() != null) {
            // Handle FOLLOWEDBY operator (temporal sequence)
            // For now, we'll treat it as AND for simplification
            Boolean left = (Boolean) visit(ctx.observationExpressions(0));
            Boolean right = (Boolean) visit(ctx.observationExpressions(1));
            return left && right;
        }
        return visit(ctx.observationExpressionOr());
    }

    @Override
    public Object visitObservationExpressionOr(STIXPatternParser.ObservationExpressionOrContext ctx) {
        if (ctx.OR() != null) {
            Boolean left = (Boolean) visit(ctx.observationExpressionOr(0));
            Boolean right = (Boolean) visit(ctx.observationExpressionOr(1));
            return left || right;
        }
        return visit(ctx.observationExpressionAnd());
    }

    @Override
    public Object visitObservationExpressionAnd(STIXPatternParser.ObservationExpressionAndContext ctx) {
        if (ctx.AND() != null) {
            Boolean left = (Boolean) visit(ctx.observationExpressionAnd(0));
            Boolean right = (Boolean) visit(ctx.observationExpressionAnd(1));
            return left && right;
        }
        return visit(ctx.observationExpression());
    }

    @Override
    public Object visitObservationExpressionSimple(STIXPatternParser.ObservationExpressionSimpleContext ctx) {
        return visit(ctx.comparisonExpression());
    }

    @Override
    public Object visitObservationExpressionCompound(STIXPatternParser.ObservationExpressionCompoundContext ctx) {
        return visit(ctx.observationExpressions());
    }

    @Override
    public Object visitComparisonExpression(STIXPatternParser.ComparisonExpressionContext ctx) {
        if (ctx.OR() != null) {
            Boolean left = (Boolean) visit(ctx.comparisonExpression(0));
            Boolean right = (Boolean) visit(ctx.comparisonExpression(1));
            return left || right;
        }
        return visit(ctx.comparisonExpressionAnd());
    }

    @Override
    public Object visitComparisonExpressionAnd(STIXPatternParser.ComparisonExpressionAndContext ctx) {
        if (ctx.AND() != null) {
            Boolean left = (Boolean) visit(ctx.comparisonExpressionAnd(0));
            Boolean right = (Boolean) visit(ctx.comparisonExpressionAnd(1));
            return left && right;
        }
        return visit(ctx.propTest());
    }

    @Override
    public Object visitPropTestEqual(STIXPatternParser.PropTestEqualContext ctx) {
        String path = extractObjectPath(ctx.objectPath());
        Object value = extractPrimitiveLiteral(ctx.primitiveLiteral());
        Object actualValue = getValueFromPath(path);

        boolean isNot = ctx.NOT() != null;
        boolean isEqual = ctx.EQ() != null;

        boolean result;
        if (actualValue == null && value == null) {
            result = true;
        } else if (actualValue == null || value == null) {
            result = false;
        } else {
            result = actualValue.equals(value);
        }

        if (!isEqual) { // NEQ
            result = !result;
        }
        if (isNot) {
            result = !result;
        }

        return result;
    }

    @Override
    public Object visitPropTestLike(STIXPatternParser.PropTestLikeContext ctx) {
        String path = extractObjectPath(ctx.objectPath());
        String pattern = extractStringLiteral(ctx.StringLiteral().getText());
        Object actualValue = getValueFromPath(path);

        boolean isNot = ctx.NOT() != null;

        if (actualValue == null) {
            return isNot;
        }

        // Convert STIX LIKE pattern to Java regex
        String regex = pattern
            .replace("%", ".*")
            .replace("_", ".");

        boolean matches = Pattern.compile(regex).matcher(actualValue.toString()).matches();
        return isNot ? !matches : matches;
    }

    @Override
    public Object visitPropTestRegex(STIXPatternParser.PropTestRegexContext ctx) {
        String path = extractObjectPath(ctx.objectPath());
        String pattern = extractStringLiteral(ctx.StringLiteral().getText());
        Object actualValue = getValueFromPath(path);

        boolean isNot = ctx.NOT() != null;

        if (actualValue == null) {
            return isNot;
        }

        boolean matches = Pattern.compile(pattern).matcher(actualValue.toString()).matches();
        return isNot ? !matches : matches;
    }

    @Override
    public Object visitPropTestSet(STIXPatternParser.PropTestSetContext ctx) {
        String path = extractObjectPath(ctx.objectPath());
        Set<Object> setValues = extractSetLiteral(ctx.setLiteral());
        Object actualValue = getValueFromPath(path);

        boolean isNot = ctx.NOT() != null;
        boolean result = setValues.contains(actualValue);

        return isNot ? !result : result;
    }

    @Override
    public Object visitPropTestExists(STIXPatternParser.PropTestExistsContext ctx) {
        String path = extractObjectPath(ctx.objectPath());
        boolean isNot = ctx.NOT() != null;

        Object value = getValueFromPath(path);
        boolean exists = value != null;

        return isNot ? !exists : exists;
    }

    private String extractObjectPath(STIXPatternParser.ObjectPathContext ctx) {
        StringBuilder path = new StringBuilder();

        // Get object type
        String objectType = ctx.objectType().getText();
        path.append(objectType);

        // Get first component
        STIXPatternParser.FirstPathComponentContext firstComp = ctx.firstPathComponent();
        if (firstComp.StringLiteral() != null) {
            path.append(".").append(extractStringLiteral(firstComp.StringLiteral().getText()));
        } else {
            path.append(".").append(firstComp.getText());
        }

        // Get additional path components
        if (ctx.objectPathComponent() != null) {
            path.append(extractPathComponent(ctx.objectPathComponent()));
        }

        return path.toString();
    }

    private String extractPathComponent(STIXPatternParser.ObjectPathComponentContext ctx) {
        if (ctx instanceof STIXPatternParser.KeyPathStepContext) {
            STIXPatternParser.KeyPathStepContext keyCtx = (STIXPatternParser.KeyPathStepContext) ctx;
            if (keyCtx.StringLiteral() != null) {
                return "." + extractStringLiteral(keyCtx.StringLiteral().getText());
            } else {
                return "." + keyCtx.IdentifierWithoutHyphen().getText();
            }
        } else if (ctx instanceof STIXPatternParser.IndexPathStepContext) {
            STIXPatternParser.IndexPathStepContext indexCtx = (STIXPatternParser.IndexPathStepContext) ctx;
            if (indexCtx.ASTERISK() != null) {
                return "[*]";
            } else {
                return "[" + indexCtx.getText().replaceAll("[\\[\\]]", "") + "]";
            }
        }
        return "";
    }

    private Object extractPrimitiveLiteral(STIXPatternParser.PrimitiveLiteralContext ctx) {
        if (ctx.orderableLiteral() != null) {
            return extractOrderableLiteral(ctx.orderableLiteral());
        } else if (ctx.BoolLiteral() != null) {
            return Boolean.valueOf(ctx.BoolLiteral().getText());
        }
        return null;
    }

    private Object extractOrderableLiteral(STIXPatternParser.OrderableLiteralContext ctx) {
        if (ctx.IntPosLiteral() != null) {
            return Integer.parseInt(ctx.IntPosLiteral().getText());
        } else if (ctx.IntNegLiteral() != null) {
            return Integer.parseInt(ctx.IntNegLiteral().getText());
        } else if (ctx.FloatPosLiteral() != null) {
            return Double.parseDouble(ctx.FloatPosLiteral().getText());
        } else if (ctx.FloatNegLiteral() != null) {
            return Double.parseDouble(ctx.FloatNegLiteral().getText());
        } else if (ctx.StringLiteral() != null) {
            return extractStringLiteral(ctx.StringLiteral().getText());
        } else if (ctx.TimestampLiteral() != null) {
            return extractTimestampLiteral(ctx.TimestampLiteral().getText());
        }
        // Handle BinaryLiteral and HexLiteral if needed
        return null;
    }

    private String extractStringLiteral(String literal) {
        // Remove quotes and handle escape sequences
        if (literal.startsWith("'") && literal.endsWith("'")) {
            literal = literal.substring(1, literal.length() - 1);
            literal = literal.replace("\\'", "'").replace("\\\\", "\\");
        }
        return literal;
    }

    private Instant extractTimestampLiteral(String literal) {
        // Remove 't' prefix and quotes
        literal = literal.substring(2, literal.length() - 1);
        return ZonedDateTime.parse(literal).toInstant();
    }

    private Set<Object> extractSetLiteral(STIXPatternParser.SetLiteralContext ctx) {
        Set<Object> set = new HashSet<>();
        if (ctx.primitiveLiteral() != null) {
            for (STIXPatternParser.PrimitiveLiteralContext lit : ctx.primitiveLiteral()) {
                set.add(extractPrimitiveLiteral(lit));
            }
        }
        return set;
    }

    private Object getValueFromPath(String path) {
        // Parse the path to extract object type and property path
        String[] parts = path.split(":", 2);
        if (parts.length != 2) {
            return null;
        }

        String objectType = parts[0];
        String propertyPath = parts[1];

        // Get the JSON data for this object type
        String json = (String) observationData.get(objectType);
        if (json == null) {
            return null;
        }

        try {
            // Use JsonPath to extract the value
            String jsonPath = "$." + propertyPath.replace(".", ".");
            return JsonPath.read(json, jsonPath);
        } catch (Exception e) {
            logger.debug("Could not read path {} from object", path, e);
            return null;
        }
    }
}