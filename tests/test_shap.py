from explainability.shap_explainer import SHAPExplainer


def main():

    print("\n" + "=" * 60)
    print("SHAP EXPLAINER TEST")
    print("=" * 60)

    explainer = SHAPExplainer()

    # ---------------------------------------------
    # Dummy feature dictionary
    # ---------------------------------------------

    features = {}

    for feature in explainer.top_features:
        features[feature] = 1.0

    # ---------------------------------------------
    # Generate explanation
    # ---------------------------------------------

    explanation = explainer.explain_flow(features)

    print("\nTop 5 SHAP Features\n")

    for index, feature in enumerate(explanation, start=1):

        print(
            f"{index}. "
            f"{feature['feature']}"
            f" | Value: {feature['value']:.4f}"
            f" | Impact: {feature['impact']:.6f}"
        )

    print("\nSHAP TEST PASSED")


if __name__ == "__main__":
    main()